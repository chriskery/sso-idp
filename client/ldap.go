package client

import (
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"sync"
)

var (
	once sync.Once
	lc   *LdapClient
)

func NewLdapClient() *LdapClient {
	once.Do(func() {
		lc = &LdapClient{ldapConfig{}}
		if err := viper.UnmarshalKey("ldap", &lc.ldapConfig); err != nil {
			log.Fatalln(err)
		}
	})
	return lc
}

type ldapConfig struct {
	Addr             string `mapstructure:"addr"`
	BindDN           string `mapstructure:"bindDN"`
	BindDNCredential string `mapstructure:"bindDN_credential"`
	SearchBase       string `mapstructure:"search_base" v`
}

type LdapClient struct {
	ldapConfig
}

func (client *LdapClient) getConn(username, password string) (*ldap.Conn, error) {
	conn, err := ldap.DialURL(client.Addr)
	if err != nil {
		return nil, err
	}

	if _, err = conn.SimpleBind(&ldap.SimpleBindRequest{
		Username: username,
		Password: password,
	}); err != nil {
		return nil, err
	}
	return conn, nil
}

func (client *LdapClient) getConnWithAdmin() (*ldap.Conn, error) {
	return client.getConn(client.BindDN, client.BindDNCredential)
}

func (client *LdapClient) sendRequest(
	request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	conn, err := client.getConnWithAdmin()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.Search(request)
}

const (
	ldapAttributeCN             = "cn"
	ldapAttributeGidNumber      = "gidNumber"
	ldapAttributeMemberUid      = "memberUid"
	ldapAttributeUid            = "uid"
	ldapAttributeUidNumber      = "uidNumber"
	ldapAttributePrimaryGroupID = "primaryGroupID"
	ldapAttributeEmail          = "mail"
)

func (client *LdapClient) Authenticate(username, password string) (map[string][]string, error) {
	attributes := []string{
		ldapAttributeCN,
		ldapAttributeGidNumber,
		ldapAttributeMemberUid,
		ldapAttributeUid,
		ldapAttributeUidNumber,
		ldapAttributeEmail,
	}
	request := buildSearchRequest(client.SearchBase, fmt.Sprintf("(cn=%s)", username), attributes)
	result, err := client.sendRequest(request)
	if err != nil {
		return nil, errors.New("can not find user's DN")
	}
	for _, entry := range result.Entries {
		if conn, err := client.getConn(entry.DN, password); err != nil {
			log.Error(err)
			continue
		} else {
			conn.Close()
		}
		return client.getAttributes(entry, attributes), nil
	}
	return nil, errors.New(ldap.LDAPResultCodeMap[ldap.LDAPResultNoSuchObject])
}

func (client *LdapClient) getAttributes(entry *ldap.Entry, attributes []string) map[string][]string {
	attrs := make(map[string][]string)
	for _, attribute := range attributes {
		attrs[attribute] = entry.GetAttributeValues(attribute)
	}
	return attrs
}

func buildSearchRequest(dn string,
	filter string, attributes []string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(dn,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		attributes,
		nil)
}
