package certs

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
	"os/user"
	"reflect"
	"tasadar.net/tionis/ssh-tools/util"
	"time"
)

type ChangeRequest struct {
	IdentifierOverride  sql.NullString
	PrincipalsOverride  []string
	PrincipalsToAdd     []string
	PrincipalsToRemove  []string
	ExtensionsOverride  map[string]string
	ExtensionsToAdd     map[string]string
	ExtensionsToRemove  []string
	ValidBeforeOverride sql.NullTime
	ValidAfterOverride  sql.NullTime
	TimePattern         sql.NullString
}

type Cert struct {
	Cert *ssh.Certificate
}

func FromBytes(certBytes []byte) (*Cert, error) {
	certAsKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %w", err)
	}
	return &Cert{Cert: certAsKey.(*ssh.Certificate)}, nil
}

func FromFile(certPath string) (*Cert, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert: %w", err)
	}
	return FromBytes(certBytes)
}

func FromStdin() (*Cert, error) {
	certBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert: %w", err)
	}
	return FromBytes(certBytes)
}

func (c *Cert) Renew(conf SigningConfig, changes ChangeRequest) error {
	if !conf.IgnoreExpiry && c.Cert.ValidBefore < uint64(time.Now().Unix()) {
		log.Println("cert is expired")
		return fmt.Errorf("cert is expired")
	}

	err := c.ApplyChanges(changes)
	if err != nil {
		return err
	}

	return c.Sign(conf)
}

func (c *Cert) ApplyChanges(changes ChangeRequest) error {
	if changes.IdentifierOverride.Valid {
		c.Cert.KeyId = changes.IdentifierOverride.String
	}

	if changes.PrincipalsOverride != nil {
		c.Cert.ValidPrincipals = changes.PrincipalsOverride
	} else {
		if changes.PrincipalsToAdd != nil {
			c.Cert.ValidPrincipals = append(c.Cert.ValidPrincipals, changes.PrincipalsToAdd...)
		}
		if changes.PrincipalsToRemove != nil {
			for _, principal := range changes.PrincipalsToRemove {
				for i, p := range c.Cert.ValidPrincipals {
					if p == principal {
						c.Cert.ValidPrincipals = append(c.Cert.ValidPrincipals[:i], c.Cert.ValidPrincipals[i+1:]...)
						break
					}
				}
			}
		}
	}

	if changes.ExtensionsOverride != nil {
		c.Cert.Extensions = changes.ExtensionsOverride
	} else {
		if changes.ExtensionsToAdd != nil {
			for k, v := range changes.ExtensionsToAdd {
				c.Cert.Extensions[k] = v
			}
		}
		if changes.ExtensionsToRemove != nil {
			for _, k := range changes.ExtensionsToRemove {
				delete(c.Cert.Extensions, k)
			}
		}
	}

	if changes.TimePattern.Valid {
		err := c.ApplyTimePattern(changes.TimePattern.String)
		if err != nil {
			return err
		}
	} else {
		originalDuration := time.Unix(int64(c.Cert.ValidBefore), 0).Sub(time.Unix(int64(c.Cert.ValidAfter), 0))
		if changes.ValidAfterOverride.Valid {
			c.Cert.ValidAfter = uint64(changes.ValidAfterOverride.Time.Unix())
		} else {
			c.Cert.ValidAfter = uint64(time.Now().Unix())
		}
		if changes.ValidBeforeOverride.Valid {
			c.Cert.ValidBefore = uint64(changes.ValidBeforeOverride.Time.Unix())
		} else {
			validAfter := time.Unix(int64(c.Cert.ValidAfter), 0).Add(originalDuration)
			c.Cert.ValidBefore = uint64(validAfter.Unix())
		}
	}
	return nil
}

func DefaultUserCert() *Cert {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	var username string
	u, err := user.Current()
	if err != nil {
		username = "unknown"
	} else {
		username = u.Username
	}
	return &Cert{Cert: &ssh.Certificate{
		Key:             nil,
		Serial:          0,
		CertType:        ssh.UserCert,
		KeyId:           hostname + "@tionis.dev",
		ValidPrincipals: []string{username},
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(1 * time.Hour).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		}}}
}

// Sign signs the cert with the given CA key. If ignoreExpiry is true, the cert
// will be signed even if it is already expired. If the cert is expired and
// ignoreExpiry is false, an error will be returned.
// This will change the cert's ValidAfter and ValidBefore fields to compensate
// for clock inaccuracy given in conf.
func (c *Cert) Sign(conf SigningConfig) error {
	if !conf.IgnoreExpiry && c.Cert.ValidBefore < uint64(time.Now().Unix()) {
		log.Println("cert is expired")
		return fmt.Errorf("cert is expired")
	}

	if conf.WasRevoked(c.Cert) {
		return fmt.Errorf("cert was revoked, refusing to sign")
	}

	c.Cert.ValidAfter = uint64(time.Unix(int64(c.Cert.ValidAfter), 0).Add(-1 * conf.ClockInaccuracyCompensation).Unix())
	c.Cert.ValidBefore = uint64(time.Unix(int64(c.Cert.ValidBefore), 0).Add(conf.ClockInaccuracyCompensation).Unix())

	err := c.Cert.SignCert(rand.Reader, conf.CAKey)
	if err != nil {
		return fmt.Errorf("failed to sign cert: %w", err)
	}
	return nil
}

func (c *Cert) Verify(validKeys []ssh.PublicKey) error {
	for _, key := range validKeys {
		err := key.Verify(c.Cert.Marshal(), c.Cert.Signature)
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("cert was not signed by any of the given keys")
}

func (c *Cert) ApplyTimePattern(pattern string) error {
	validAfter, validBefore, err := util.ParseTimePattern(pattern)
	if err != nil {
		return fmt.Errorf("failed to parse time pattern: %w", err)
	}
	c.Cert.ValidAfter = uint64(validAfter.Unix())
	c.Cert.ValidBefore = uint64(validBefore.Unix())
	return nil
}

func (c *Cert) SetPrincipals(principals []string) {
	c.Cert.ValidPrincipals = principals
}

func (c *Cert) SetIdentifier(identifier string) {
	c.Cert.KeyId = identifier
}

func (c *Cert) SetKeyFromBytes(keyBytes []byte) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse key: %w", err)
	}
	c.Cert.Key = key
	return nil
}

func (c *Cert) AttachCertToSigner(signer ssh.Signer) (ssh.Signer, error) {
	if signer.PublicKey().Type() != c.Cert.Key.Type() {
		return nil, fmt.Errorf("key types do not match")
	}
	if !reflect.DeepEqual(signer.PublicKey().Marshal(), c.Cert.Key.Marshal()) {
		return nil, fmt.Errorf("keys do not match")
	}
	return ssh.NewCertSigner(c.Cert, signer)
}

func (c *Cert) SetValidAfter(validAfter time.Time) {
	c.Cert.ValidAfter = uint64(validAfter.Unix())
}

func (c *Cert) SetValidBefore(validBefore time.Time) {
	c.Cert.ValidBefore = uint64(validBefore.Unix())
}

func (c *Cert) SetExtension(key string, value string) {
	c.Cert.Extensions[key] = value
}

func (c *Cert) UnsetExtension(key string) {
	delete(c.Cert.Extensions, key)
}

func (c *Cert) SetCriticalOption(key string, value string) {
	c.Cert.Permissions.CriticalOptions[key] = value
}

func (c *Cert) UnsetCriticalOption(key string) {
	delete(c.Cert.Permissions.CriticalOptions, key)
}

func (c *Cert) Marshal() []byte {
	return ssh.Marshal(c.Cert)
}

func (c *Cert) MarshalAuthorizedKey() []byte {
	return ssh.MarshalAuthorizedKey(c.Cert)
}

func (c *Cert) SetKey(key ssh.PublicKey) {
	c.Cert.Key = key
}
