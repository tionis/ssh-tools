package sigchain

import (
	"database/sql"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net/http"
	"os"
	"tasadar.net/tionis/ssh-tools/certs"
)

type Sigchain struct {
	TrustedKeys []ssh.PublicKey
	Address     Address
	Nodes       []SigchainNode
}

type SigchainNode struct{}

func (s *Sigchain) VerifyCert(cert *certs.Cert) error {
	// TODO verify cert
	err := cert.Verify(s.TrustedKeys)
	if err != nil {
		return fmt.Errorf("failed to verify cert: %w", err)
	}
	return nil
}

func ParseSigchain(data []byte) ([]SigchainNode, error) {
	// TODO parse sigchain
	return nil, errors.New("not implemented")
}

func (s *Sigchain) MergeSigchainUpdates(updates []SigchainNode) error {
	// TODO merge updates into sigchain
	return errors.New("not implemented")
}

func (s *Sigchain) Update() error {
	switch s.Address.ConnectionType {
	case "https", "http":
		resp, err := http.Get(s.Address.ConnectionType + "://" + s.Address.ConnectionAddr)
		if err != nil {
			return fmt.Errorf("failed to get sigchain: %w", err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read sigchain: %w", err)
		}
		parsed, err := ParseSigchain(data)
		if err != nil {
			return fmt.Errorf("failed to parse sigchain: %w", err)
		}
		s.MergeSigchainUpdates(parsed)
	case "sftp":
		// just download file
		// TODO implement sftp
	case "ssh":
		// ssh $address sigchain $optional_newest_node
		// TODO implement ssh
	default:
		return errors.New("unsupported connection type")
	}
	return nil
}

func (s *Sigchain) ApplyUpdates(updates []SigchainNode) error {
	// TODO apply updates to sigchain (to be used for out-of-band updates)
	return errors.New("not implemented")
}

func New(path string, trustAnchor sql.NullString) (*Sigchain, error) {
	_, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// TODO parse fileData
	return &Sigchain{}, nil
}
