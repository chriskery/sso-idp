package idp

import (
	"github.com/chriskery/sso-idp/model"
)

// LoginType type of credential used for authentication
type LoginType int

const (
	// CertificateLogin user logged in via certificate
	CertificateLogin LoginType = iota
	// PasswordLogin user logged in via password
	PasswordLogin
)

// Auditor is responsible for capturing login events
type Auditor interface {
	LogSuccess(*model.User, *model.AuthnRequest, LoginType)
}

type auditor struct{}

func (a *auditor) LogSuccess(*model.User, *model.AuthnRequest, LoginType) {
	// Default audit doesn't do anything
}

// DefaultAuditor returns a do nothing Auditor implementation
func DefaultAuditor() Auditor {
	return &auditor{}
}
