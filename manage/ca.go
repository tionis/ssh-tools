package manage

import (
	"errors"
	"tasadar.net/tionis/ssh-tools/certs"
)

type CACertManager struct {
	// TODO
}

func NewCAManager(homeDir string) *CACertManager {
	// TODO
	return &CACertManager{}
}

func (c *CACertManager) ProcessRequests(processRenewals bool, processRevocation bool, processNewCerts bool) error {
	// TODO implement
	// pull requests from server
	// process
	// log
	// push response
	return errors.New("not implemented")
}

func (c *CACertManager) UpdateRevocationList() error {
	// TODO implement
	// pull revocation list from server
	// check signatures
	return errors.New("not implemented")
}

func (c *CACertManager) RevokeCert(cert *certs.Cert) error {
	// TODO
	return nil
}
