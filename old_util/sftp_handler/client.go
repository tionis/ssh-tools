package sftp_handler

import (
	"fmt"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type SFTPClient struct {
	Remote *SFTPRemote
	Conn   *ssh.Client
	Client *sftp.Client
}

func (s *SFTPClient) Close() error {
	err := s.Client.Close()
	if err != nil {
		return fmt.Errorf("failed to close sftp connection: %w", err)
	}
	err = s.Conn.Close()
	if err != nil {
		return fmt.Errorf("failed to close ssh connection: %w", err)
	}
	return nil
}
