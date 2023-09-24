package sftp_handler

import (
	"errors"
	"fmt"
	"github.com/pkg/sftp"
	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
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

func ParseSFTPRemote(signingConf certs.SigningConfig, homeDir, remote string) (*SFTPRemote, error) {
	// TODO use .ssh/config to process remotes
	parse, err := url.Parse(remote)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Remote: %w", err)
	}
	if parse.Scheme != "sftp" {
		return nil, errors.New("not a sftp Remote")
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
	// BUG I think this doesn't handle cert-authorities in known_hosts
	knownHostsCallback, err := knownhosts.New(path.Join(homeDir, ".ssh", "known_hosts"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse known_hosts: %w", err)
	}

	rootKey, err := certs.GetTemporaryRootKey(signingConf)
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

func SFTPGetClient(signingConf certs.SigningConfig, homeDir, remoteString string) (*SFTPClient, error) {
	var client SFTPClient
	var err error
	client.Remote, err = ParseSFTPRemote(signingConf, homeDir, remoteString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Remote: %w", err)
	}
	client.Conn, err = ssh.Dial(
		"tcp",
		net.JoinHostPort(client.Remote.Host, client.Remote.Port),
		&client.Remote.SSHConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial Remote: %w", err)
	}
	client.Client, err = sftp.NewClient(client.Conn)
	if err != nil {
		return nil, fmt.Errorf("failed to create sftp Client: %w", err)
	}
	return &client, nil
}
