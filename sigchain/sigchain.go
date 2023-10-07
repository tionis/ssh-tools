package sigchain

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
	"io"
	"net/http"
	"os"
	"strings"
	"tasadar.net/tionis/ssh-tools/certs"
)

type Sigchain struct {
	TrustedKeys []ssh.PublicKey
	Address     Address
	Nodes       []Node
}

type Hash struct {
	HashType sshsig.HashAlgorithm
	Hash     []byte
}

type Node struct {
	Signature  *sshsig.Signature
	ParentHash Hash
	Cert       *certs.Cert
}

func (s *Sigchain) VerifyCert(cert *certs.Cert) error {
	// TODO verify cert
	err := cert.Verify(s.TrustedKeys)
	if err != nil {
		return fmt.Errorf("failed to verify cert: %w", err)
	}
	return nil
}

func ParseSigchain(data []byte) ([]Node, error) {
	// TODO parse sigchain
	return nil, errors.New("not implemented")
}

func (s *Sigchain) MergeSigchainUpdates(updates []Node) error {
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

func (s *Sigchain) ApplyUpdates(updates []Node) error {
	// TODO apply updates to sigchain (to be used for out-of-band updates)
	return errors.New("not implemented")
}

func NewFromFile(path string, trustAnchor sql.NullString) (*Sigchain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines)%2 != 0 {
		return nil, errors.New("invalid sigchain file")
	}
	var root *Hash
	//if trustAnchor.Valid {
	//	root = parseHash(trustAnchor.String)
	//}
	sig := &Sigchain{
		TrustedKeys: make([]ssh.PublicKey, 0),
		Address: Address{
			RootHash: root,
		},
		Nodes: make([]Node, len(lines)/2),
	}
	for i := 0; i < len(lines); i += 2 {
		err := json.Unmarshal([]byte(lines[i]), &sig.Nodes[i/2])
		if err != nil {
			return nil, fmt.Errorf("failed to parse sigchain line_num=%d: %w", i, err)
		}
		sig.Nodes[i/2].Signature, err = sshsig.ParseSignature([]byte(lines[i+1]))
	}

	// TODO parse fileData
	return &Sigchain{}, nil
}
