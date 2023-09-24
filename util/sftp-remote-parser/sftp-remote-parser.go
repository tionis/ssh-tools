package sftp_remote_parser

import (
	"errors"
	"fmt"
	"github.com/pkg/sftp"
	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"net/url"
	"path"
	"strings"
	"tasadar.net/tionis/ssh-tools/certs"
)

type SFTPRemote struct {
	SSHConfig ssh.ClientConfig
	Host      string
	Port      string
	Path      string
}

func ParseSFTPRemote(homeDir, remote string) (*SFTPRemote, error) {
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

	// TODO find a better way to handle known_hosts (rely on internal cert signed trust store?)
	knownHostsCallback, err := knownhosts.New(path.Join(homeDir, ".ssh", "known_hosts"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse known_hosts: %w", err)
	}

	rootKey, err := certs.GetTemporaryRootKey()
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
		SSHConfig: sshConfig,
		Host:      parse.Hostname(),
		Port:      port,
		Path:      strings.TrimPrefix(parse.Path, "/"),
	}, nil
}

// TODO rewrite this to return a os.File to work on
func renewRemoteCert(homeDir, remoteString string, signingConf certs.SigningConfig, changes certs.ChangeRequest) error {
	remote, err := ParseSFTPRemote(homeDir, remoteString)
	if err != nil {
		return fmt.Errorf("failed to parse remote: %w", err)
	}
	conn, err := ssh.Dial("tcp", net.JoinHostPort(remote.Host, remote.Port), &remote.SSHConfig)
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
	log.Printf("opening remote file: %s\n", remote.Path)

	file, err := sfConn.Open(remote.Path)
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

	cert, err := certs.FromBytes(fileBytes)
	if err != nil {
		return fmt.Errorf("failed to parse cert: %w", err)
	}
	err = cert.Renew(signingConf, changes)
	if err != nil {
		return fmt.Errorf("failed to renew cert: %w", err)
	}
	err = cert.Sign(signingConf)
	if err != nil {
		return fmt.Errorf("failed to sign cert: %w", err)
	}

	_, err = file.Write(cert.MarshalAuthorizedKey())
	if err != nil {
		return fmt.Errorf("failed to write cert to file: %w", err)
	}
	return nil
}
