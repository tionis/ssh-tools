package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/hiddeco/sshsig"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"log/slog"
	"os"
	"path"
	"strings"
	"tasadar.net/tionis/ssh-tools/allowed_signers"
	"tasadar.net/tionis/ssh-tools/certs"
	"tasadar.net/tionis/ssh-tools/manage"
	proxyClient "tasadar.net/tionis/ssh-tools/proxy/client"
	proxyServer "tasadar.net/tionis/ssh-tools/proxy/server"
	"tasadar.net/tionis/ssh-tools/util"
	"tasadar.net/tionis/ssh-tools/util/sftp_handler"
	"time"
)

// TODO add ssh subcommand
// TODO implement management and automatic renewals using upstream ssh-tool server
// (implement server in this repo for easier containment?)
// think of new name for this project
// think of ways to make this project importable for a single binary
// across git-tools, ssh-tools, shell-tools, etc
// instant renewal over ssh-tools server and patch bay

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var logger *slog.Logger
	var fishCompletion string
	var allowedSigners allowed_signers.AllowedSigners
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Println("failed to get home dir: ", err)
		return
	}

	app := &cli.App{
		EnableBashCompletion: true,
		Flags: []cli.Flag{
			&cli.PathFlag{
				Name:      "allowed_signers",
				Aliases:   []string{"s"},
				Usage:     "sigchain file to use",
				Value:     path.Join(homeDir, ".ssh", "allowed_signers"),
				TakesFile: true,
			},
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"ll"},
				Usage:   "log level to use",
				Value:   "info",
			},
		},
		Before: func(c *cli.Context) error {
			logLevel, err := parseLogLevel(c.String("log-level"))
			if err != nil {
				return fmt.Errorf("failed to parse log level: %w", err)
			}
			addSource := false
			if logLevel == slog.LevelDebug {
				addSource = true
			}
			logger = slog.New(
				slog.NewTextHandler(
					os.Stdout,
					&slog.HandlerOptions{
						AddSource: addSource,
						Level:     logLevel,
					}))
			data, err := os.ReadFile(c.Path("allowed_signers"))
			if err != nil {
				return fmt.Errorf("failed to read allowed signers: %w", err)
			}
			allowedSigners, err = allowed_signers.ParseAllowedSigners(data)
			if err != nil {
				return fmt.Errorf("failed to parse allowed signers: %w", err)
			}
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:  "proxy",
				Usage: "commands for websocket proxy",
				Subcommands: []*cli.Command{
					{
						Name:  "server",
						Usage: "start a websocket proxy server",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:  "addr",
								Usage: "address to listen on",
								Value: "0.0.0.0:80",
							},
							&cli.StringFlag{
								Name:  "authorized-keys",
								Usage: "path to authorized keys file",
								Value: path.Join(homeDir, ".ssh", "authorized_keys"),
							},
						},
						Action: func(c *cli.Context) error {
							file, err := os.ReadFile(c.Path("authorized-keys"))
							if err != nil {
								return fmt.Errorf("failed to read authorized keys: %w", err)
							}
							keys, err := util.ParseAuthorizedKeys(file)
							if err != nil {
								return err
							}
							server, err := proxyServer.New(logger, "", keys, c.String("addr"))
							if err != nil {
								return err
							}
							return server.Start()
						},
					},
					{
						Name: "client",
						Usage: "start a websocket proxy client\n" +
							"use as `ProxyCommand ssh-proxy \"base_url\" %h %p",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:  "key",
								Usage: "path to key to use",
							},
						},
						Action: func(c *cli.Context) error {
							var signer ssh.Signer
							if c.String("key") != "" {
								signer, err = util.GetSignerFromFile(c.Path("key"))
							} else {
								signer, err = util.GetDefaultSigner()
							}
							if err != nil {
								return fmt.Errorf("failed to get signer: %w", err)
							}
							client, err := proxyClient.New(logger, signer)
							if err != nil {
								return fmt.Errorf("failed to create client: %w", err)
							}
							return client.Connect(strings.Join(c.Args().Slice(), "/"))
						},
					},
				},
			},
			{
				Name:    "cert",
				Aliases: []string{"c"},
				Usage:   "certificate management",
				Subcommands: []*cli.Command{
					{
						Name:    "create",
						Aliases: []string{"c"},
						Usage:   "create a cert for a local key",
						Flags: cliFlagAddChangeRequestAndSigningConfig(
							&cli.BoolFlag{
								Name:  "stdin",
								Usage: "read key from stdin instead of file",
							},
							&cli.PathFlag{
								Name:    "key",
								Aliases: []string{"k"},
								Usage:   "path to key to sign",
								Value:   path.Join(homeDir, ".ssh", "id_ed25519.pub"),
							},
							&cli.StringFlag{
								Name:  "sftp",
								Usage: "sign key on remote using sftp",
							},
						),
						Action: func(c *cli.Context) error {
							changes := cliFlagsToChangeRequest(c)
							signingConf, err := cliFlagsToSigningConfig(c)
							if err != nil {
								return fmt.Errorf("failed to parse signing config: %w", err)
							}
							cert := certs.DefaultUserCert()
							err = cert.ApplyChanges(changes)
							if err != nil {
								return fmt.Errorf("failed to apply changes: %w", err)
							}
							var reader io.Reader
							var writer io.Writer
							var closer func() error

							if c.Bool("stdin") {
								reader = os.Stdin
								writer = os.Stdout
								closer = func() error { return nil }
							} else {
								if c.String("sftp") != "" {
									sftpClient, err := sftp_handler.SFTPGetClient(
										signingConf,
										homeDir,
										c.String("sftp"))
									if err != nil {
										return fmt.Errorf("failed to parse get sftp file: %w", err)
									}
									if c.String("identifier") == "" {
										cert.SetIdentifier(sftpClient.Remote.Host + "@tionis.dev")
									}
									keyFile, err := sftpClient.Client.OpenFile(sftpClient.Remote.Path, os.O_RDWR)
									if err != nil {
										return err
									}
									certFile, err := sftpClient.Client.Create(strings.TrimSuffix(sftpClient.Remote.Path, ".pub") + "-cert.pub")
									reader = keyFile
									writer = certFile
									closer = func() error {
										err := keyFile.Close()
										if err != nil {
											return fmt.Errorf("failed to close key file: %w", err)
										}
										err = certFile.Close()
										if err != nil {
											return fmt.Errorf("failed to close cert file: %w", err)
										}
										return sftpClient.Close()
									}
								} else {
									keyFile, err := os.Open(c.Path("key"))
									if err != nil {
										return fmt.Errorf("failed to open key file: %w", err)
									}
									certFile, err := os.Create(strings.TrimSuffix(c.Path("key"), ".pub") + "-cert.pub")
									if err != nil {
										return fmt.Errorf("failed to create cert file: %w", err)
									}
									reader = keyFile
									writer = certFile
									closer = func() error {
										err := keyFile.Close()
										if err != nil {
											return fmt.Errorf("failed to close key file: %w", err)
										}
										err = certFile.Close()
										if err != nil {
											return fmt.Errorf("failed to close cert file: %w", err)
										}
										return nil
									}
								}
							}

							keyBytes, err := io.ReadAll(reader)
							if err != nil {
								return fmt.Errorf("failed to read key: %w", err)
							}
							err = cert.SetKeyFromBytes(keyBytes)
							if err != nil {
								return fmt.Errorf("failed to set key: %w", err)
							}
							err = cert.Sign(signingConf)
							if err != nil {
								return fmt.Errorf("failed to sign cert: %w", err)
							}

							_, err = writer.Write(cert.MarshalAuthorizedKey())
							if err != nil {
								return fmt.Errorf("failed to write cert: %w", err)
							}
							closeErr := closer()
							if closeErr != nil {
								return fmt.Errorf("failed to close: %w", closeErr)
							}
							return nil
						},
					},
					{
						Name:    "renew",
						Aliases: []string{"r"},
						Usage:   "renew a certificate from stdin or file",
						Flags: cliFlagAddChangeRequestAndSigningConfig(
							&cli.BoolFlag{
								Name:  "stdin",
								Usage: "read cert from stdin instead of file",
							},
							&cli.StringFlag{
								Name:  "sftp",
								Usage: "renew cert on remote using sftp",
							},
							&cli.PathFlag{
								Name:    "cert",
								Aliases: []string{"c"},
								Usage:   "path to cert to renew",
								Value:   path.Join(homeDir, ".ssh", "id_ed25519-cert.pub"),
							},
							&cli.BoolFlag{
								Name:  "dont-verify",
								Usage: "don't verify cert before renewal",
							},
						),
						Action: func(c *cli.Context) error {
							changes := cliFlagsToChangeRequest(c)
							signingConf, err := cliFlagsToSigningConfig(c)
							if err != nil {
								return fmt.Errorf("failed to parse signing config: %w", err)
							}
							var certBytes []byte
							var writer io.Writer
							var closer func() error

							if c.Bool("stdin") {
								certBytes, err = io.ReadAll(os.Stdin)
								if err != nil {
									return fmt.Errorf("failed to read cert from stdin: %w", err)
								}
								writer = os.Stdout
								closer = func() error { return nil }
							} else {
								if c.String("sftp") != "" {
									sftpClient, err := sftp_handler.SFTPGetClient(
										signingConf,
										homeDir,
										c.String("sftp"))
									if err != nil {
										return fmt.Errorf("failed to parse get sftp file: %w", err)
									}
									certFile, err := sftpClient.Client.OpenFile(
										sftpClient.Remote.Path,
										os.O_RDWR)
									certBytes, err = io.ReadAll(certFile)
									if err != nil {
										return fmt.Errorf("failed to read cert from file: %w", err)
									}
									_, err = certFile.Seek(0, io.SeekStart)
									if err != nil {
										return fmt.Errorf("failed to seek to start of file: %w", err)
									}
									writer = certFile
									closer = func() error {
										err = certFile.Close()
										if err != nil {
											return fmt.Errorf("failed to close cert file: %w", err)
										}
										return sftpClient.Close()
									}
								} else {
									// TODO check if cert is loaded in agent
									// if it is, save it to be replaced after renewal
									certFile, err := os.OpenFile(
										c.Path("cert"),
										os.O_RDWR,
										0644)
									if err != nil {
										return fmt.Errorf("failed to create cert file: %w", err)
									}
									certBytes, err = io.ReadAll(certFile)
									if err != nil {
										return fmt.Errorf("failed to read cert from file: %w", err)
									}
									_, err = certFile.Seek(0, io.SeekStart)
									if err != nil {
										return fmt.Errorf("failed to seek to start of file: %w", err)
									}
									writer = certFile
									closer = func() error {
										err = certFile.Close()
										if err != nil {
											return fmt.Errorf("failed to close cert file: %w", err)
										}
										return nil
									}
								}
							}
							cert, err := certs.FromBytes(certBytes)
							if err != nil {
								return fmt.Errorf("failed to parse cert: %w", err)
							}
							if !c.Bool("dont-verify") {
								err = allowedSigners.CertChecker.CheckCert(cert.Cert.ValidPrincipals[0], cert.Cert)
								if err != nil {
									return fmt.Errorf("failed to verify cert: %w", err)
								}
							}
							err = cert.Renew(signingConf, changes)
							if err != nil {
								return fmt.Errorf("failed to sign cert: %w", err)
							}
							_, err = writer.Write(cert.MarshalAuthorizedKey())
							if err != nil {
								return fmt.Errorf("failed to write cert: %w", err)
							}
							closeErr := closer()
							if closeErr != nil {
								return fmt.Errorf("failed to close: %w", closeErr)
							}
							return nil
						},
					},
					{
						Name:    "info",
						Aliases: []string{"i"},
						Usage:   "get info about a certificate",
						Flags: []cli.Flag{
							&cli.PathFlag{
								Name:    "cert",
								Aliases: []string{"c"},
								Usage:   "path to cert to check",
								Value:   path.Join(homeDir, ".ssh", "id_ed25519-cert.pub"),
							},
							&cli.BoolFlag{
								Name:  "stdin",
								Usage: "read cert from stdin instead of file",
							},
							&cli.StringFlag{
								Name:  "sftp",
								Usage: "read cert from remote using sftp",
							},
						},
						Action: func(c *cli.Context) error {
							var cert *certs.Cert
							if c.Bool("stdin") {
								cert, err = certs.FromStdin()
								if err != nil {
									return fmt.Errorf("failed to read cert from stdin: %w", err)
								}
							} else {
								if c.String("sftp") != "" {
									signingConf, err := cliFlagsToSigningConfig(c)
									if err != nil {
										return fmt.Errorf("failed to parse signing config: %w", err)
									}
									client, err := sftp_handler.SFTPGetClient(
										signingConf,
										homeDir,
										c.String("sftp"))
									if err != nil {
										return fmt.Errorf("failed to get SFTP client for remote: %w", err)
									}
									open, err := client.Client.Open(client.Remote.Path)
									if err != nil {
										return fmt.Errorf("failed to open cert file: %w", err)
									}
									cert, err = certs.FromReader(open)
									if err != nil {
										return fmt.Errorf("failed to read cert from file: %w", err)
									}
									err = open.Close()
									if err != nil {
										return fmt.Errorf("failed to close cert file: %w", err)
									}
									err = client.Close()
									if err != nil {
										return fmt.Errorf("failed to close sftp client: %w", err)
									}
								} else {
									cert, err = certs.FromFile(c.Path("cert"))
									if err != nil {
										return fmt.Errorf("failed to read cert from file: %w", err)
									}
								}
							}
							indent, err := json.MarshalIndent(cert.Cert, "", "  ")
							if err != nil {
								return fmt.Errorf("failed to marshal cert: %w", err)
							}
							fmt.Println(string(indent))
							return nil
						},
					},
					{
						Name:    "verify",
						Aliases: []string{"v"},
						Usage:   "verify a certificate",
						Flags: []cli.Flag{
							&cli.PathFlag{
								Name:    "cert",
								Aliases: []string{"c"},
								Usage:   "path to cert to check",
								Value:   path.Join(homeDir, ".ssh", "id_ed25519-cert.pub"),
							},
							&cli.BoolFlag{
								Name:  "stdin",
								Usage: "read cert from stdin instead of file",
							},
							&cli.StringFlag{
								Name:  "sftp",
								Usage: "read cert from remote using sftp",
							},
						},
						UsageText: "principal to check",
						Action: func(c *cli.Context) error {
							var cert *certs.Cert
							if len(c.Args().Slice()) != 1 {
								return fmt.Errorf("principal to check is required")
							}
							if c.Bool("stdin") {
								cert, err = certs.FromStdin()
								if err != nil {
									return fmt.Errorf("failed to read cert from stdin: %w", err)
								}
							} else {
								if c.String("sftp") != "" {
									signingConf, err := cliFlagsToSigningConfig(c)
									if err != nil {
										return fmt.Errorf("failed to parse signing config: %w", err)
									}
									client, err := sftp_handler.SFTPGetClient(
										signingConf,
										homeDir,
										c.String("sftp"))
									open, err := client.Client.Open(client.Remote.Path)
									if err != nil {
										return fmt.Errorf("failed to open cert file: %w", err)
									}
									cert, err = certs.FromReader(open)
									if err != nil {
										return fmt.Errorf("failed to read cert from file: %w", err)
									}
									err = open.Close()
									if err != nil {
										return fmt.Errorf("failed to close cert file: %w", err)
									}
									err = client.Close()
									if err != nil {
										return fmt.Errorf("failed to close sftp client: %w", err)
									}
								} else {
									cert, err = certs.FromFile(c.Path("cert"))
									if err != nil {
										return fmt.Errorf("failed to read cert from file: %w", err)
									}
								}
							}
							err := allowedSigners.CertChecker.CheckCert(c.Args().First(), cert.Cert)
							if err != nil {
								return fmt.Errorf("failed to verify cert: %w", err)
							}
							return nil
						},
					},
					{
						Name: "auto-renew",
						Flags: []cli.Flag{
							&cli.PathFlag{
								Name:    "key",
								Aliases: []string{"k"},
								Usage:   "path to key to sign",
								Value:   path.Join(homeDir, ".ssh", "id_ed25519.pub"),
							},
						},
						Usage: "automatically request renewal of certificate when it has reached " +
							"50% of its validity time window",
						Action: func(c *cli.Context) error {
							userManager := manage.NewUserManager(homeDir)
							cert, err := certs.FromFile(c.Path("cert"))
							if err != nil {
								return fmt.Errorf("failed to read cert from file: %w", err)
							}
							if userManager.RenewalInProgress(cert) {
								log.Println("a cert renewal is already requested, checkinf for reply")
								return userManager.ProcessCertRenewal(cert)
							}
							now := uint64(time.Now().Unix())
							timePassed := now - cert.Cert.ValidAfter
							totalValidTime := cert.Cert.ValidBefore - cert.Cert.ValidAfter
							if timePassed*100/totalValidTime > 50 {
								log.Println("requesting cert renewal, run again to process answer")
								return userManager.RequestCertRenewal(cert)
							}
							log.Println("not renewing cert")
							return nil
						},
					},
					{
						Name: "self-revocation",
						Subcommands: []*cli.Command{
							{
								Name: "create",
								Flags: []cli.Flag{
									&cli.PathFlag{
										Name:    "key",
										Aliases: []string{"k"},
										Usage:   "path to key to revoke itself",
										Value:   path.Join(homeDir, ".ssh", "id_ed25519"),
									},
									&cli.BoolFlag{
										Name:  "stdin",
										Usage: "read key from stdin instead of file",
									},
								},
								Usage: "revoke a ssh key by signing it's own revocation",
								Action: func(c *cli.Context) error {
									var keyBytes []byte
									if c.Bool("stdin") {
										keyBytes, err = io.ReadAll(os.Stdin)
										if err != nil {
											return fmt.Errorf("failed to read key: %w", err)
										}
									} else {
										keyBytes, err = os.ReadFile(c.Path("key"))
										if err != nil {
											return fmt.Errorf("failed to read key: %w", err)
										}
									}
									key, err := ssh.ParsePrivateKey(keyBytes)
									if err != nil {
										return fmt.Errorf("failed to parse key: %w", err)
									}

									//fmt.Println(string(ssh.MarshalAuthorizedKey(key.PublicKey())))
									// TODO embed timestamp in signed statement after which the key is invalid
									pubKeyString := ssh.MarshalAuthorizedKey(key.PublicKey())
									signature, err := sshsig.Sign(
										bytes.NewReader(pubKeyString[:len(pubKeyString)-1]),
										key,
										sshsig.HashSHA512,
										"ssh-revocation")
									if err != nil {
										return fmt.Errorf("failed to sign key: %w", err)
									}

									fmt.Print(string(pubKeyString))
									fmt.Print(string(sshsig.Armor(signature)))
									return nil
								},
							},
							{
								Name: "verify",
								Flags: []cli.Flag{
									&cli.PathFlag{
										Name:    "key",
										Aliases: []string{"k"},
										Usage:   "path to key to validate revocation",
									},
									&cli.BoolFlag{
										Name:  "stdin",
										Usage: "read key from stdin instead of file",
									},
									&cli.BoolFlag{
										Name:    "quiet",
										Aliases: []string{"q"},
									},
								},
								Usage: "validate a self-signed ssh key revocation",
								Action: func(c *cli.Context) error {
									var signatureBytes []byte
									if c.Bool("stdin") {
										signatureBytes, err = io.ReadAll(os.Stdin)
										if err != nil {
											return fmt.Errorf("failed to read key: %w", err)
										}
									} else {
										signatureBytes, err = os.ReadFile(c.Path("key"))
										if err != nil {
											return fmt.Errorf("failed to read key: %w", err)
										}
									}
									parts := strings.Split(string(signatureBytes), "\n")
									pubKeyString := parts[0]
									pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyString))
									signature, err := sshsig.Unarmor([]byte(strings.Join(parts[1:], "\n")))
									if err != nil {
										return err
									}
									err = sshsig.Verify(
										bytes.NewReader([]byte(pubKeyString)),
										signature,
										pubKey,
										sshsig.HashSHA512,
										"ssh-revocation")
									if err != nil {
										return err
									}
									if !c.Bool("quiet") {
										fmt.Printf("key revocation for %s is valid\n", pubKeyString)
									}
									return nil
								},
							},
						},
					},
				},
			},
			{
				Name:    "manage",
				Aliases: []string{"m"},
				Usage:   "manage certificates across devices",
				Subcommands: []*cli.Command{
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
							caManager := manage.NewCAManager(homeDir)
							return caManager.ProcessRequests(c.Bool("renew"), c.Bool("revoke"), c.Bool("new"))
						},
					},
					{
						Name:    "update-revocation-list",
						Aliases: []string{"u"},
						Usage:   "update the revocation list",
						Action: func(c *cli.Context) error {
							caManager := manage.NewCAManager(homeDir)
							return caManager.UpdateRevocationList()
						},
					},
					{
						Name:    "revoke",
						Aliases: []string{"rv"},
						Flags: []cli.Flag{
							&cli.PathFlag{
								Name:    "cert",
								Aliases: []string{"c"},
								Usage:   "path to cert to revoke",
							},
						},
						Usage: "revoke a certificate from stdin or file when given as $1",
						Action: func(c *cli.Context) error {
							var cert *certs.Cert
							var err error
							if c.Path("cert") != "" {
								cert, err = certs.FromFile(c.Path("cert"))
								if err != nil {
									return fmt.Errorf("failed to read cert from file: %w", err)
								}
							} else {
								cert, err = certs.FromStdin()
								if err != nil {
									return fmt.Errorf("failed to read cert from stdin: %w", err)
								}
							}
							caManager := manage.NewCAManager(homeDir)
							return caManager.RevokeCert(cert)
						},
					},
				},
			},
			{
				Name:    "util",
				Aliases: []string{"u"},
				Usage:   "utility functions",
				Subcommands: []*cli.Command{
					{
						Name:    "completions",
						Aliases: []string{"c"},
						Usage:   "generate completions for shell",
						Subcommands: []*cli.Command{
							{
								Name:    "fish",
								Aliases: []string{"f"},
								Usage:   "generate completions for fish shell",
								Action: func(c *cli.Context) error {
									fmt.Println(fishCompletion)
									return nil
								},
							},
						},
					},
				},
			},
		},
	}

	fishCompletion, err = app.ToFishCompletion()
	if err != nil {
		return
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("failed to run app: %v", err)
	}
}

func parseLogLevel(logLevel string) (slog.Level, error) {
	switch logLevel {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log level: %s", logLevel)
	}
}

func cliFlagAddChangeRequestAndSigningConfig(flags ...cli.Flag) []cli.Flag {
	return append(append(flags, cliFlagsChangeRequest...), cliFlagsSigningConfig...)
}

var cliFlagsChangeRequest = []cli.Flag{
	&cli.StringFlag{
		Name:    "time",
		Aliases: []string{"t"},
		Usage:   "override validity time with pattern (like used by ssh-keygen)",
	},
	&cli.StringSliceFlag{
		Name:    "principal-add",
		Aliases: []string{"pa"},
		Usage:   "principals to add to cert",
	},
	&cli.StringSliceFlag{
		Name:    "principal-rm",
		Aliases: []string{"pr"},
		Usage:   "principals to remove from cert",
	},
	&cli.StringSliceFlag{
		Name:    "principal",
		Aliases: []string{"p"},
		Usage:   "principals to override to cert",
	},
	&cli.StringFlag{
		Name:    "identifier",
		Aliases: []string{"I"},
		Usage:   "override identifier to use",
	},
	&cli.TimestampFlag{ // TODO replace with time pattern
		Name:    "valid-after",
		Aliases: []string{"va"},
		Usage:   "override valid after date",
		Layout:  "2006-01-02 15:04:05",
	},
	&cli.TimestampFlag{ // TODO replace with time pattern
		Name:    "valid-before",
		Aliases: []string{"vb"},
		Usage:   "override valid before date",
		Layout:  "2006-01-02 15:04:05",
	},
}

func cliFlagsToChangeRequest(c *cli.Context) certs.ChangeRequest {
	var timePattern, identifier sql.NullString
	if c.String("time") != "" {
		timePattern = sql.NullString{String: c.String("time"), Valid: true}
	}
	if c.String("identifier") != "" {
		identifier = sql.NullString{String: c.String("identifier"), Valid: true}
	}
	var validBefore, validAfter sql.NullTime
	if c.Timestamp("valid-before") != nil {
		validBefore = sql.NullTime{Time: *c.Timestamp("valid-before"), Valid: true}
	}
	if c.Timestamp("valid-after") != nil {
		validAfter = sql.NullTime{Time: *c.Timestamp("valid-after"), Valid: true}
	}
	var extensionsToAdd, extensionsOverride map[string]string
	if c.StringSlice("extension-add") != nil {
		extensionsToAdd = make(map[string]string)
		for _, extension := range c.StringSlice("extension-add") {
			extensionsToAdd[extension] = ""
		}
	}
	if c.StringSlice("extension") != nil {
		extensionsOverride = make(map[string]string)
		for _, extension := range c.StringSlice("extension") {
			extensionsOverride[extension] = ""
		}
	}
	return certs.ChangeRequest{
		IdentifierOverride:  identifier,
		PrincipalsOverride:  c.StringSlice("principal"),
		PrincipalsToAdd:     c.StringSlice("principal-add"),
		PrincipalsToRemove:  c.StringSlice("principal-rm"),
		ExtensionsOverride:  extensionsOverride,
		ExtensionsToAdd:     extensionsToAdd,
		ExtensionsToRemove:  c.StringSlice("extension-rm"),
		ValidAfterOverride:  validAfter,
		ValidBeforeOverride: validBefore,
		TimePattern:         timePattern,
	}
}

var cliFlagsSigningConfig = []cli.Flag{
	&cli.BoolFlag{
		Name:    "ignore-expiry",
		Aliases: []string{"i"},
		Usage:   "ignore expiry date of certificate",
	},
	&cli.DurationFlag{
		Name:    "clock-compensation",
		Aliases: []string{"cc"},
		Usage:   "how much time to add/substract to compensate for clock inaccuracies",
		Value:   3 * time.Minute,
	},
}

func cliFlagsToSigningConfig(c *cli.Context) (certs.SigningConfig, error) {
	return certs.CreateSigningConf(
		c.Duration("clock-compensation"),
		c.Bool("ignore-expiry"))
}
