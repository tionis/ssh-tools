package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/sftp"
	"github.com/skeema/knownhosts"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"
)

type key struct {
	mu     sync.Mutex
	yk     *piv.YubiKey
	serial uint32
	pubk   ssh.PublicKey
	privk  crypto.PrivateKey
	signer ssh.Signer
	// touchNotification is armed by Sign to show a notification if waiting for
	// more than a few seconds for the touch operation. It is paused and reset
	// by getPIN so it won't fire while waiting for the PIN.
	touchNotification *time.Timer
}

func main() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Println("failed to get home dir: ", err)
		return
	}
	hostName, err := os.Hostname()
	if err != nil {
		log.Println("failed to get hostname: ", err)
		return
	}

	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:    "short-cert-info",
				Aliases: []string{"sci"},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "cert",
						Aliases: []string{"c"},
						Usage:   "path to cert to check",
						Value:   path.Join(homeDir, ".ssh", "id_ed25519-cert.pub"),
					},
				},
				Usage: "get short info about a certificate",
				Action: func(c *cli.Context) error {
					cert, err := parseCertFile(c.String("cert"))
					if err != nil {
						return fmt.Errorf("failed to parse cert: %w", err)
					}
					now := uint64(time.Now().Unix())
					timePassed := now - cert.ValidAfter
					timeRemaining := cert.ValidBefore - now
					msgLevel := 0
					if timeRemaining <= 0 {
						msgLevel = 8
					} else if timeRemaining < 60*60 {
						msgLevel = 8
					} else if timePassed*100/(timePassed+timeRemaining) > 50 && timeRemaining < 1*24*60*60 {
						msgLevel = 8
					} else if timePassed*100/(timePassed+timeRemaining) > 50 {
						msgLevel = 4
					}
					switch msgLevel {
					case 0:
						fmt.Printf("%s%s/%s%s",
							color.White,
							renderTime(timePassed),
							renderTime(timeRemaining),
							color.Reset)
					case 4:
						fmt.Printf("%s%s/%s%s",
							color.Yellow,
							renderTime(timePassed),
							renderTime(timeRemaining),
							color.Reset)
					case 8:
						fmt.Printf("%s%s/%s%s",
							color.Red,
							renderTime(timePassed),
							renderTime(timeRemaining),
							color.Reset)
					}
					return nil
				},
			},
			{
				Name: "auto-renew",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "key",
						Aliases: []string{"k"},
						Usage:   "path to key to sign",
						Value:   path.Join(homeDir, ".ssh", "id_ed25519.pub"),
					},
				},
				Usage: "automatically request renewal of certificate when it has reached " +
					"50% of its validity and less than 30 days remain\n" +
					"this should be run as a cron job @hourly or */15 or smth similar",
				Action: func(c *cli.Context) error {
					cert, err := parseCertFile(c.String("cert"))
					if err != nil {
						return fmt.Errorf("failed to parse cert: %w", err)
					}
					now := uint64(time.Now().Unix())
					timePassed := now - cert.ValidAfter
					timeRemaining := cert.ValidBefore - now
					if timePassed*100/(timePassed*100+timeRemaining*100) < 50 && timeRemaining < 30*24*60*60 {
						log.Println("requesting cert renewal, run again to process answer")
						return requestRenewal(cert)
					}
					log.Println("not renewing cert")
					return nil
				},
			},
			{
				Name:    "renew-remote",
				Aliases: []string{"rr"},
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "remote",
						Aliases:  []string{"r"},
						Required: true,
						Usage:    "remote sftp path to sign",
					},
					&cli.BoolFlag{
						Name:    "ignore-expiry",
						Aliases: []string{"i"},
						Usage:   "ignore expiry date of certificate",
					},
				},
				Usage: "renew certificate on remote server",
				Action: func(c *cli.Context) error {
					return renewRemoteCert(homeDir, c.String("remote"), c.Bool("ignore-expiry"))
				},
			},
			{
				Name:  "get-cert-expiry-seconds",
				Usage: "get the expiry date of a certificate in seconds",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "cert",
						Aliases: []string{"c"},
						Usage:   "path to cert to check",
						Value:   path.Join(homeDir, ".ssh", "id_ed25519-cert.pub"),
					},
				},
				Action: func(c *cli.Context) error {
					cert, err := parseCertFile(c.String("cert"))
					if err != nil {
						return fmt.Errorf("failed to parse cert: %w", err)
					}
					fmt.Println(cert.ValidBefore - uint64(time.Now().Unix()))
					return nil
				},
			},
			{
				Name:  "get-cert-expiry-percent",
				Usage: "get the expiry date of a certificate as a percentage",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "cert",
						Aliases: []string{"c"},
						Usage:   "path to cert to check",
						Value:   path.Join(homeDir, ".ssh", "id_ed25519-cert.pub"),
					},
				},
				Action: func(c *cli.Context) error {
					cert, err := parseCertFile(c.String("cert"))
					if err != nil {
						return fmt.Errorf("failed to parse cert: %w", err)
					}
					now := uint64(time.Now().Unix())
					timePassed := now - cert.ValidAfter
					timeRemaining := cert.ValidBefore - now
					fmt.Printf(
						"%.2f%%\n",
						float64(timePassed)/float64(timePassed+timeRemaining)*100)
					return nil
				},
			},
			{
				Name:    "get-cert-info",
				Aliases: []string{"i"},
				Usage:   "get info about a certificate",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "cert",
						Aliases: []string{"c"},
						Usage:   "path to cert to check",
						Value:   path.Join(homeDir, ".ssh", "id_ed25519-cert.pub"),
					},
				},
				Action: func(c *cli.Context) error {
					cert, err := parseCertFile(c.String("cert"))
					if err != nil {
						return fmt.Errorf("failed to parse cert: %w", err)
					}
					indent, err := json.MarshalIndent(cert, "", "  ")
					if err != nil {
						return fmt.Errorf("failed to marshal cert: %w", err)
					}
					fmt.Println(string(indent))
					return nil
				},
			},
			{
				Name:    "revoke",
				Aliases: []string{"rv"},
				Usage:   "revoke a certificate from stdin or file when given as $1",
				Action: func(c *cli.Context) error {
					var cert *ssh.Certificate
					var err error
					if c.Args().Len() > 0 {
						cert, err = parseCertFile(c.Args().First())
						if err != nil {
							return fmt.Errorf("failed to read cert from file: %w", err)
						}
					} else {
						cert, err = parseCertStdin()
						if err != nil {
							return fmt.Errorf("failed to read cert from stdin: %w", err)
						}
					}
					return revokeCert(cert)
				},
			},
			{
				Name:    "update-revocation-list",
				Aliases: []string{"u"},
				Usage:   "update the revocation list",
				Action: func(c *cli.Context) error {
					return updateRevocationList()
				},
			},
			{
				Name:    "process",
				Aliases: []string{"p"},
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "renew",
						Aliases: []string{"r"},
						Usage:   "only process renewals (automatically)",
					},
					&cli.BoolFlag{
						Name:    "revoke",
						Aliases: []string{"rv"},
						Usage:   "only process revocations (automatically)",
					},
					&cli.BoolFlag{
						Name:    "new",
						Aliases: []string{"n"},
						Usage:   "only process new requests, must be approved by admin interactively",
					},
				},
				Usage: "process certificate signing requests",
				Action: func(c *cli.Context) error {
					return processRequests(c.Bool("renew"), c.Bool("revoke"), c.Bool("new"))
				},
			},
			{
				Name:    "renew",
				Aliases: []string{"r"},
				Usage:   "renew a certificate from stdin or file when given as $1",
				Action: func(c *cli.Context) error {
					var certBytesIn []byte
					if c.Args().Len() > 0 {
						certBytesIn, err = os.ReadFile(c.Args().First())
						if err != nil {
							return fmt.Errorf("failed to read cert from file: %w", err)
						}
					} else {
						certBytesIn, err = io.ReadAll(os.Stdin)
						if err != nil {
							return fmt.Errorf("failed to read cert from stdin: %w", err)
						}
					}

					cert, err := renewCert(certBytesIn, false)
					if err != nil {
						return fmt.Errorf("failed to renew cert: %w", err)
					}

					if c.Args().Len() > 0 {
						err := os.WriteFile(c.Args().First(), ssh.MarshalAuthorizedKey(cert), 0600)
						if err != nil {
							return fmt.Errorf("failed to write cert to file: %w", err)
						}
					} else {
						_, err := os.Stdout.Write(ssh.MarshalAuthorizedKey(cert))
						if err != nil {
							return fmt.Errorf("failed to write cert to stdout: %w", err)
						}
					}

					return nil
				},
			},
			{
				Name:    "sign",
				Aliases: []string{"s"},
				Usage:   "sign a local key",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "time",
						Aliases: []string{"t"},
						Usage:   "validity time pattern",
						Value:   "1h",
					},
					&cli.StringFlag{
						Name:    "key",
						Aliases: []string{"k"},
						Usage:   "path to key to sign",
						Value:   path.Join(homeDir, ".ssh", "id_ed25519.pub"),
					},
					&cli.StringFlag{
						Name:    "principals",
						Aliases: []string{"p"},
						Usage:   "principals to add to cert",
						Value:   "tionis",
					},
					&cli.StringFlag{
						Name:    "identifier",
						Aliases: []string{"i"},
						Usage:   "identifier to use",
						Value:   hostName + "@tionis.dev",
					},
				},
				Action: func(c *cli.Context) error {
					caKey, err := newKey()
					if err != nil {
						log.Println("failed to get caKey: ", err)
						return fmt.Errorf("failed to get caKey: %w", err)
					}
					return createNewCert(caKey, c.String("time"), c.String("key"), c.String("principals"), c.String("identifier"))
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("failed to run app: %v", err)
	}
}

func processRequests(processRenewals bool, processRevocation bool, processNewCerts bool) error {
	// TODO implement
	// pull requests from server
	// process
	// log
	// push response
	return errors.New("not implemented")
}

func updateRevocationList() error {
	// TODO implement
	// pull revocation list from server
	// check signatures
	return errors.New("not implemented")
}

func createNewCert(caKey ssh.Signer, timePattern string, keyPath string, principals string, identifier string) error {
	keyToSignBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key to sign: %w", err)
	}
	keyToSign, _, _, _, err := ssh.ParseAuthorizedKey(keyToSignBytes)
	if err != nil {
		return fmt.Errorf("failed to parse key to sign: %w", err)
	}

	var certToSign ssh.Certificate
	certToSign.Key = keyToSign
	certToSign.KeyId = identifier
	certToSign.Extensions = make(map[string]string)
	certToSign.Extensions["permit-X11-forwarding"] = ""
	certToSign.Extensions["permit-agent-forwarding"] = ""
	certToSign.Extensions["permit-port-forwarding"] = ""
	certToSign.Extensions["permit-pty"] = ""
	certToSign.Extensions["permit-user-rc"] = ""
	certToSign.CertType = ssh.UserCert
	certToSign.ValidPrincipals = strings.Split(principals, ",")

	duration, err := time.ParseDuration(timePattern)
	if err != nil {
		return fmt.Errorf("failed to parse duration: %w", err)
	}
	certToSign.ValidBefore = uint64(time.Now().Add(duration).Unix())
	certToSign.ValidAfter = uint64(time.Now().Unix())

	err = certToSign.SignCert(rand.Reader, caKey)
	if err != nil {
		return fmt.Errorf("failed to sign cert: %w", err)
	}
	certToSign.Marshal()
	bytes := ssh.MarshalAuthorizedKey(&certToSign)

	certKeyPath := strings.TrimSuffix(keyPath, ".pub") + "-cert.pub"
	return os.WriteFile(certKeyPath, bytes, 0600)
}

func getAgent() (agent.Agent, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH_AUTH_SOCK: %w", err)
	}
	sshAgent := agent.NewClient(conn)
	return sshAgent, nil
}

func renewRemoteCert(homeDir, remoteString string, ignoreExpiry bool) error {
	remote, err := parseSFTPRemote(homeDir, remoteString)
	if err != nil {
		return fmt.Errorf("failed to parse remote: %w", err)
	}
	conn, err := ssh.Dial("tcp", net.JoinHostPort(remote.host, remote.port), &remote.sshConfig)
	if err != nil {
		return fmt.Errorf("failed to dial remote: %w", err)
	}
	defer func(conn *ssh.Client) {
		err := conn.Close()
		if err != nil {
			log.Println("failed to close ssh connection: ", err)
		}
	}(conn)
	sfConn, err := sftp.NewClient(conn)
	if err != nil {
		return fmt.Errorf("failed to create sftp client: %w", err)
	}
	defer func(sfConn *sftp.Client) {
		err := sfConn.Close()
		if err != nil {
			log.Println("failed to close sftp connection: ", err)
		}
	}(sfConn)
	log.Println("opened connection to remote")
	log.Printf("opening remote file: %s\n", remote.path)
	file, err := sfConn.Open(remote.path)
	if err != nil {
		return fmt.Errorf("failed to open remote file: %w", err)
	}
	defer func(file *sftp.File) {
		err := file.Close()
		if err != nil {
			log.Println("failed to close file: ", err)
		}
	}(file)
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to start of file: %w", err)
	}
	cert, err := renewCert(fileBytes, ignoreExpiry)
	if err != nil {
		return fmt.Errorf("failed to renew cert: %w", err)
	}
	_, err = file.Write(ssh.MarshalAuthorizedKey(cert))
	if err != nil {
		log.Println("failed to write cert to file: ", err)
		return fmt.Errorf("failed to write cert to file: %w", err)
	}
	return nil
}

func revokeCert(cert *ssh.Certificate) error {
	// TODO implement
	// sign revocation statement
	// log
	// upload it
	return errors.New("not implemented")
}

func parseCertStdin() (*ssh.Certificate, error) {
	certBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	certAsKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, err
	}
	return certAsKey.(*ssh.Certificate), nil
}

func parseCertFile(certPath string) (*ssh.Certificate, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	certAsKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, err
	}
	return certAsKey.(*ssh.Certificate), nil
}

func getCAKeyFromAgent(caPubKeys []ssh.PublicKey) (ssh.Signer, error) {
	sshAgent, err := getAgent()
	if err != nil {
		return nil, err
	}
	signers, err := sshAgent.Signers()
	if err != nil {
		return nil, err
	}
	for _, signer := range signers {
		for _, caPubKey := range caPubKeys {
			if ssh.FingerprintSHA256(caPubKey) == ssh.FingerprintSHA256(signer.PublicKey()) {
				return signer, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching caKey found")
}

func openYK() (yk *piv.YubiKey, err error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("no YubiKey detected")
	}
	// TODO: support multiple YubiKeys. For now, select the first one that opens
	// successfully, to skip any internal unused smart card readers.
	for _, card := range cards {
		yk, err = piv.Open(card)
		if err == nil {
			return
		}
	}
	return
}

func (k *key) getPIN() (string, error) {
	if k.touchNotification != nil && k.touchNotification.Stop() {
		defer k.touchNotification.Reset(5 * time.Second)
	}
	r, err := k.yk.Retries()
	if err != nil {
		return "", fmt.Errorf("failed to get retries: %w", err)
	}
	return getPIN(k.serial, r)
}

func newKey() (*key, error) {
	ykRaw, err := openYK()
	if err != nil {
		return nil, fmt.Errorf("failed to open YubiKey: %w", err)
	}
	serial, err := ykRaw.Serial()
	if err != nil {
		return nil, err
	}
	pk, err := getPublicKey(ykRaw, piv.SlotSignature)
	if err != nil {
		return nil, err
	}
	k := &key{
		yk:                ykRaw,
		serial:            serial,
		pubk:              pk,
		privk:             nil,
		signer:            nil,
		touchNotification: nil,
	}
	priv, err := ykRaw.PrivateKey(
		piv.SlotSignature,
		pk.(ssh.CryptoPublicKey).CryptoPublicKey(),
		piv.KeyAuth{PINPrompt: k.getPIN},
	)
	if err != nil {
		return nil, err
	}
	k.privk = priv
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare signer: %w", err)
	}
	k.signer = s
	return k, nil
}

func parseAuthorizedKeys(b []byte) ([]ssh.PublicKey, error) {
	var keys []ssh.PublicKey
	for len(b) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			return nil, err
		}
		keys = append(keys, pubKey)
		b = rest
	}
	return keys, nil
}

func getPublicKey(yk *piv.YubiKey, slot piv.Slot) (ssh.PublicKey, error) {
	cert, err := yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("could not get public key: %w", err)
	}
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
	case *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("unexpected public key type: %T", cert.PublicKey)
	}
	pk, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to process public key: %w", err)
	}
	return pk, nil
}

func (k *key) PublicKey() ssh.PublicKey {
	return k.pubk
}

func (k *key) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	signed, err := k.signer.Sign(rand, data)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k.touchNotification = time.NewTimer(5 * time.Second)
	go func() {
		select {
		case <-k.touchNotification.C:
		case <-ctx.Done():
			k.touchNotification.Stop()
			return
		}
		showNotification("Waiting for YubiKey touch...")
	}()
	if err != nil {
		return nil, err
	}
	return signed, err
}

func showNotification(message string) {
	switch runtime.GOOS {
	case "darwin":
		message = strings.ReplaceAll(message, `\`, `\\`)
		message = strings.ReplaceAll(message, `"`, `\"`)
		appleScript := `display notification "%s" with title "yubikey-agent"`
		err := exec.Command("osascript", "-e", fmt.Sprintf(appleScript, message)).Run()
		if err != nil {
			log.Println("failed to show notification: ", err)
		}
	case "linux":
		err := exec.Command("notify-send", "-i", "dialog-password", "yubikey-agent", message).Run()
		if err != nil {
			log.Println("failed to show notification: ", err)
		}
	}
}

type SFTPRemote struct {
	sshConfig ssh.ClientConfig
	host      string
	port      string
	path      string
}

func parseSFTPRemote(homeDir, remote string) (*SFTPRemote, error) {
	parse, err := url.Parse(remote)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote: %w", err)
	}
	if parse.Scheme != "sftp" {
		return nil, errors.New("not a sftp remote")
	}
	user := parse.User.Username()
	if user == "" {
		// default to os.User?
		return nil, errors.New("no user specified")
	}
	port := parse.Port()
	if port == "" {
		port = "22"
	}

	// TODO generate short lived key and cert with root permissions

	knownHostsCallback, err := knownhosts.New(path.Join(homeDir, ".ssh", "known_hosts"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse known_hosts: %w", err)
	}

	rootKey, err := getTemporaryRootKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get root key: %w", err)
	}

	sshConfig := ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(rootKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		//HostKeyCallback: knownHostsCallback.HostKeyCallback(),
		HostKeyAlgorithms: knownHostsCallback.HostKeyAlgorithms(
			net.JoinHostPort(parse.Hostname(), port)),
		BannerCallback: ssh.BannerDisplayStderr(),
	}
	return &SFTPRemote{
		sshConfig: sshConfig,
		host:      parse.Hostname(),
		port:      port,
		path:      strings.TrimPrefix(parse.Path, "/"),
	}, nil
}

func getTemporaryRootKey() (ssh.Signer, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	caKey, err := newKey()
	if err != nil {
		log.Println("failed to get caKey: ", err)
		return nil, err
	}
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to process public key: %w", err)
	}

	certToSign := ssh.Certificate{
		Key:   sshPubKey,
		KeyId: "root@tionis.dev",
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          ""},
		},
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"root", "admin", "*", "citadel"},
		ValidBefore:     uint64(time.Now().Add(1 * time.Minute).Unix()),
		ValidAfter:      uint64(time.Now().Add(-1 * time.Minute).Unix()),
	}

	err = certToSign.SignCert(rand.Reader, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign cert: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare signer: %w", err)
	}
	certSigner, err := ssh.NewCertSigner(&certToSign, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare cert signer: %w", err)
	}
	return certSigner, nil
}

func renewCert(certBytes []byte, ignoreExpiry bool) (*ssh.Certificate, error) {
	caKey, err := newKey()
	if err != nil {
		log.Println("failed to get caKey: ", err)
		return nil, err
	}
	certAsKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	cert := certAsKey.(*ssh.Certificate)
	if cert.ValidBefore < uint64(time.Now().Unix()) {
		log.Println("cert is expired")
		return nil, fmt.Errorf("cert is expired")
	}

	// TODO update revocation list?
	// TODO check if cert was revoked

	validDuration := time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
	cert.ValidAfter = uint64(time.Now().Unix())
	cert.ValidBefore = uint64(time.Now().Add(validDuration).Unix())
	err = cert.SignCert(rand.Reader, caKey)
	if err != nil {
		log.Println("failed to sign cert: ", err)
		return nil, err
	}
	return cert, nil
}

type knownHost struct {
	marker  string
	pubkey  ssh.PublicKey
	comment string
}

func parseKnownHostsFile(path string) (map[string]knownHost, error) {
	knownHostBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	hosts := make(map[string]knownHost)
	for {
		var marker, comment string
		var hostsNames []string
		var pubkey ssh.PublicKey
		marker, hostsNames, pubkey, comment, knownHostBytes, err = ssh.ParseKnownHosts(knownHostBytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		for _, host := range hostsNames {
			hosts[host] = knownHost{
				marker:  marker,
				pubkey:  pubkey,
				comment: comment,
			}
		}
	}
	return hosts, nil
}

func requestRenewal(cert *ssh.Certificate) error {
	// TODO request renewal
	// check if there is a reply waiting
	// if not request renewal
	// else parse reply and check if it is valid
	// if not request renewal
	// else apply cert update and log
	// (keep one old cert for rollback)
	// revoke old one?
	return errors.New("not implemented")
}

func renderTime(seconds uint64) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	} else if seconds < 60*60 {
		return fmt.Sprintf("%.1fm", float64(seconds)/60)
	} else if seconds < 24*60*60 {
		return fmt.Sprintf("%.1fh", float64(seconds)/60/60)
	} else {
		return fmt.Sprintf("%.1fd", float64(seconds)/60/60/24)
	}
}
