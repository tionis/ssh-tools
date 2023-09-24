package manage

import "tasadar.net/tionis/ssh-tools/certs"

type UserCertManager struct {
	// TODO
}

func NewUserManager(homeDir string) *UserCertManager {
	// TODO
	return &UserCertManager{}
}

func (m *UserCertManager) RenewalInProgress(cert *certs.Cert) bool {
	// TODO
	return false
}

func (m *UserCertManager) ProcessCertRenewal(cert *certs.Cert) error {
	// TODO
	return nil
}

func (m *UserCertManager) RequestCertRenewal(cert *certs.Cert) error {
	// TODO
	return nil
}

func (m *UserCertManager) RequestCertRevoke(cert *certs.Cert) error {
	// TODO
	return nil
}
