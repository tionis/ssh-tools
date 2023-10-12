package agent

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// TODO add embedded ask pass

type Key struct {
	signer           ssh.Signer
	pubKey           ssh.PublicKey
	comment          string
	validUntil       sql.NullTime
	confirmBeforeUse bool
	certificate      *ssh.Certificate
	constrains       []agent.ConstraintExtension
}

type Agent struct {
	keys           map[string]*Key
	password       sql.NullString
	certs          []*Key
	encryptionKeys map[*[32]byte]*[32]byte
}

func (a *Agent) List() ([]*agent.Key, error) {
	// TODO list certs separately?
	var keys []*agent.Key
	for _, k := range a.keys {
		keys = append(keys, &agent.Key{
			Format:  k.pubKey.Type(),
			Blob:    k.pubKey.Marshal(),
			Comment: k.comment,
		})
	}
	for _, c := range a.certs {
		keys = append(keys, &agent.Key{
			Format:  c.certificate.Type(),
			Blob:    c.certificate.Marshal(),
			Comment: c.comment,
		})
	}
	return keys, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	priv, ok := a.keys[string(key.Marshal())]
	if !ok {
		return nil, errors.New("key not found")
	}
	return priv.signer.Sign(rand.Reader, data)
}

var ErrOperationUnsupported = errors.New("operation unsupported")

func (a *Agent) Add(key agent.AddedKey) error {
	// TODO add certs separately?
	var validUntil sql.NullTime
	if key.LifetimeSecs > 0 {
		validUntil = sql.NullTime{
			Time:  time.Now().Add(time.Duration(key.LifetimeSecs) * time.Second),
			Valid: true,
		}
	}
	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}
	pubKey := signer.PublicKey()

	keyToAdd := Key{
		signer:           signer,
		pubKey:           pubKey,
		comment:          key.Comment,
		validUntil:       validUntil,
		confirmBeforeUse: key.ConfirmBeforeUse,
		certificate:      key.Certificate,
		constrains:       key.ConstraintExtensions,
	}
	if key.Certificate != nil {
		a.certs = append(a.certs, &keyToAdd)
	} else {
		// IDEA transform signing key to encryption key here and add it to store
		a.keys[string(pubKey.Marshal())] = &keyToAdd
	}
	return nil
}

func (a *Agent) Remove(key ssh.PublicKey) error {
	_, ok := a.keys[string(key.Marshal())]
	if !ok {
		return errors.New("key not found")
	}
	a.keys[string(key.Marshal())] = nil
	return nil
}

func (a *Agent) RemoveAll() error {
	a.keys = make(map[string]*Key)
	return nil
}

func (a *Agent) Lock(passphrase []byte) error {
	a.password = sql.NullString{
		String: string(passphrase),
		Valid:  true,
	}
	return nil
}

func (a *Agent) Unlock(passphrase []byte) error {
	if !a.password.Valid || a.password.String != string(passphrase) {
		return errors.New("invalid passphrase")
	}
	a.password = sql.NullString{}
	return nil
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	var signers []ssh.Signer
	for _, k := range a.keys {
		signers = append(signers, k.signer)
	}
	return signers, nil
}

func (a *Agent) SignWithFlags(_ ssh.PublicKey, _ []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	return nil, ErrOperationUnsupported
}

type Message struct {
	Contents []byte
	Nonce    *[24]byte
	Source   *[32]byte
	Target   *[32]byte
}

func (a *Agent) getEncryptionKey(peerPub *[32]byte) *[32]byte {
	if key, ok := a.encryptionKeys[peerPub]; ok {
		return key
	} else {
		return nil
	}
}

func (a *Agent) DecryptBytes(contents []byte) ([]byte, error) {
	var msg Message
	err := msgpack.Unmarshal(contents, &msg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal Message: %w", err)
	}
	decrypted, success := box.Open(nil, msg.Contents, msg.Nonce, msg.Source, a.getEncryptionKey(msg.Target))
	if !success {
		return nil, errors.New("failed to decrypt Message")
	}
	return decrypted, nil
}

func (a *Agent) EncryptBytes(contents []byte, nonce *[24]byte, source, target *[32]byte) ([]byte, error) {
	msg := &Message{
		Nonce:  nonce,
		Source: source,
		Target: target,
	}
	msg.Contents = box.Seal(nil, contents, msg.Nonce, msg.Target, a.getEncryptionKey(msg.Source))
	encrypted, err := msgpack.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Message: %w", err)
	}
	return encrypted, nil
}

type ExtensionEncryptionRequest struct {
	Nonce    *[24]byte
	Source   *[32]byte
	Target   *[32]byte
	Contents []byte
}

func (a *Agent) EncryptBytesForExtension(contents []byte) ([]byte, error) {
	var req ExtensionEncryptionRequest
	err := msgpack.Unmarshal(contents, &req)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ExtensionEncryptionRequest: %w", err)
	}
	return a.EncryptBytes(req.Contents, req.Nonce, req.Source, req.Target)
}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	switch extensionType {
	case "decrypt":
		return a.DecryptBytes(contents)
	case "encrypt":
		return a.EncryptBytesForExtension(contents)
	case "add-encryption-key":
		return a.AddEncryptionKey(contents)
	case "remove-encryption-key":
		return a.RemoveEncryptionKey(contents)
	case "list-encryption-keys":
		return a.ListEncryptionKeys(contents)
	case "remove-all-encryption-keys":
		return a.RemoveAllEncryptionKeys(contents)
	default:
		return nil, ErrOperationUnsupported
	}
}

var _ agent.ExtendedAgent = &Agent{}

func (a *Agent) serveConn(c net.Conn) {
	if err := agent.ServeAgent(a, c); err != io.EOF {
		log.Println("Agent client connection ended with error:", err)
	}
}

func (a *Agent) Close() {
	// If implementing yubikey support, close the device here
}

func getPubKeyFromEncryptionKey(key [32]byte) *[32]byte {
	// TODO implement this
	return nil
}

func (a *Agent) AddEncryptionKey(contents []byte) ([]byte, error) {
	if len(contents) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	var key [32]byte
	copy(key[:], contents)
	a.encryptionKeys[getPubKeyFromEncryptionKey(key)] = &key
	return nil, nil
}

func (a *Agent) RemoveEncryptionKey(contents []byte) ([]byte, error) {
	if len(contents) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	var key [32]byte
	copy(key[:], contents)
	delete(a.encryptionKeys, &key)
	return nil, nil
}

func (a *Agent) ListEncryptionKeys(_ []byte) ([]byte, error) {
	var keys [][32]byte
	for k := range a.encryptionKeys {
		keys = append(keys, *k)
	}
	encoded, err := msgpack.Marshal(keys)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encryption keys: %w", err)
	}
	return encoded, nil
}

func (a *Agent) RemoveAllEncryptionKeys(_ []byte) ([]byte, error) {
	a.encryptionKeys = make(map[*[32]byte]*[32]byte)
	return nil, nil
}

func New() *Agent {
	return &Agent{
		keys:           make(map[string]*Key),
		encryptionKeys: make(map[*[32]byte]*[32]byte),
		certs:          make([]*Key, 0),
	}
}

func RunAgent(socketPath string) {
	if terminal.IsTerminal(int(os.Stdin.Fd())) {
		log.Println("Warning: ssh-tools agent is meant to run as a background daemon.")
		log.Println("Running multiple instances is likely to lead to conflicts.")
		log.Println("Consider using the launchd or systemd services.")
	}

	a := New()

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for range c {
			a.Close()
		}
	}()

	_ = os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0777); err != nil {
		log.Fatalln("Failed to create UNIX socket folder:", err)
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalln("Failed to listen on UNIX socket:", err)
	}

	for {
		c, err := l.Accept()
		if err != nil {
			type temporary interface {
				Temporary() bool
			}
			if err, ok := err.(temporary); ok && err.Temporary() {
				log.Println("Temporary Accept error, sleeping 1s:", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Fatalln("Failed to accept connections:", err)
		}
		go a.serveConn(c)
	}
}
