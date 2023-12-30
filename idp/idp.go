// Copyright © 2017 Aaron Donovan <amdonov@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package idp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/amdonov/xmlsig"
	"github.com/chriskery/sso-idp/model"
	"github.com/chriskery/sso-idp/saml"
	"github.com/chriskery/sso-idp/sign"
	"github.com/chriskery/sso-idp/store"
	"github.com/chriskery/sso-idp/ui"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"net"
	"net/http"
	"strings"
	"sync"
	"text/template"
)

// IDP is the main data structure for the IDP. Public members can be used to alter behavior. Otherwise defaults are fine.
type IDP struct {
	// You can include other routes by providing a router or
	// one will be created. Alternatively, you can add routes and
	// middleware to the Handler
	Router *httprouter.Router
	// Short term cache for saving state during authentication
	TempCache store.Cache
	// Longer term cache of authenticated users
	UserCache              store.Cache
	TLSConfig              *tls.Config
	PasswordValidator      PasswordValidator
	AttributeSources       []AttributeSource
	MetadataHandler        http.HandlerFunc
	ArtifactResolveHandler http.HandlerFunc
	RedirectSSOHandler     http.HandlerFunc
	RedirectSLOHandler     http.HandlerFunc
	ECPHandler             http.HandlerFunc
	PasswordLoginHandler   http.HandlerFunc
	QueryHandler           http.HandlerFunc
	Error                  func(w http.ResponseWriter, error string, code int)
	UIHandler              http.Handler
	Auditor                Auditor
	handler                http.Handler
	signer                 sign.Signer
	validator              sign.Validator

	// properties set or derived from configuration settings
	cookieName                        string
	serverName                        string
	entityID                          string
	artifactResolutionServiceLocation string
	attributeServiceLocation          string
	singleSignOnServiceLocation       string
	singleLogoutServiceLocation       string
	ecpServiceLocation                string
	postTemplate                      *template.Template
	sps                               map[string]*ServiceProvider
	EnableTLS                         bool
}

// Handler returns the IDP's http.Handler including all sub routes or an error
func (i *IDP) Handler() (http.Handler, error) {
	if i.handler == nil {
		if i.Error == nil {
			i.Error = http.Error
		}
		if i.Auditor == nil {
			i.Auditor = DefaultAuditor()
		}
		if err := i.configureConstants(); err != nil {
			return nil, err
		}
		if err := i.configureSPs(); err != nil {
			return nil, err
		}
		if err := i.configureCrypto(); err != nil {
			return nil, err
		}
		if err := i.configureStores(); err != nil {
			return nil, err
		}
		if err := i.configureValidator(); err != nil {
			return nil, err
		}
		if err := i.configureHandler(); err != nil {
			return nil, err
		}
		if err := i.buildRoutes(); err != nil {
			return nil, err
		}
		i.handler = i.Router
	}
	return i.handler, nil
}

func (i *IDP) configureConstants() error {
	pt, err := template.New("post").Parse(postTemplate)
	if err != nil {
		return err
	}
	i.postTemplate = pt
	i.cookieName = viper.GetString("cookie-name")
	serverName := viper.GetString("server-name")
	i.entityID = viper.GetString("entity-id")
	schema := "http"
	if viper.GetBool("tls_enable") {
		schema = "https"
	}
	if i.entityID == "" {
		i.entityID = fmt.Sprintf("%s://%s/", schema, serverName)
	}
	i.serverName = serverName
	i.artifactResolutionServiceLocation = fmt.Sprintf("%s%s", serverName, viper.GetString("artifact-service-path"))
	i.attributeServiceLocation = fmt.Sprintf("%s%s", serverName, viper.GetString("attribute-service-path"))
	i.singleSignOnServiceLocation = fmt.Sprintf("%s%s", serverName, viper.GetString("sso-service-path"))
	i.singleLogoutServiceLocation = fmt.Sprintf("%s%s", serverName, viper.GetString("slo-service-path"))
	i.ecpServiceLocation = fmt.Sprintf("%s%s", serverName, viper.GetString("ecp-service-path"))
	return nil
}

func (i *IDP) configureSPs() error {
	if err := initSPs(); err != nil {
		return err
	}
	var sps []*ServiceProvider
	if err := viper.UnmarshalKey("sps", &sps); err != nil {
		return err
	}
	i.sps = make(map[string]*ServiceProvider, len(sps))
	for j, sp := range sps {
		if err := sp.parseCertificate(); err != nil {
			return err
		}
		i.sps[sp.EntityID] = sps[j]
	}

	return nil
}

func initSPs() error {
	var spMetadataUrls []*SPMetadataUrl
	if err := viper.UnmarshalKey("sp-medata-urls", &spMetadataUrls); err != nil {
		return err
	}
	waitGroup := sync.WaitGroup{}
	var lock sync.Mutex
	httpClient := http.DefaultClient
	for _, spMetadataUrl := range spMetadataUrls {
		log.Infof("begin to fetch sp %s", spMetadataUrl.Url)
		waitGroup.Add(1)
		go func(url string) {
			defer waitGroup.Done()
			// Serve 256 bytes every second.
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				log.Error(err)
				return
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				log.Error(err)
				return
			}
			if resp.Body != nil {
				defer resp.Body.Close()
				lock.Lock()
				defer lock.Unlock()
				if err = SaveSpFromMetadata(resp.Body); err != nil {
					log.Error(err)
					return
				}
				log.Infof("success read sp %s metadata", url)
			} else {
				log.Infof("fail to fetch sp %s", url)
			}
		}(spMetadataUrl.Url)
	}
	waitGroup.Wait()
	return nil
}

func (i *IDP) configureCrypto() error {
	if i.TLSConfig == nil {
		tlsConfig, err := ConfigureTLS()
		if err != nil {
			return err
		}
		i.TLSConfig = tlsConfig
	}
	if len(i.TLSConfig.Certificates) == 0 {
		return errors.New("tlsConfig does not contain a certificate")
	}
	cert := i.TLSConfig.Certificates[0]
	signer, err := xmlsig.NewSignerWithOptions(cert, xmlsig.SignerOptions{
		SignatureAlgorithm: viper.GetString("signature-algorithm"),
		DigestAlgorithm:    viper.GetString("digest-algorithm"),
	})
	i.signer = signer

	i.validator = sign.NewValidator()
	return err
}

func (i *IDP) configureStores() error {
	if i.TempCache == nil {
		cache, err := store.New(viper.GetDuration("temp-cache-duration"))
		if err != nil {
			return err
		}
		i.TempCache = cache
	}
	if i.UserCache == nil {
		cache, err := store.New(viper.GetDuration("user-cache-duration"))
		if err != nil {
			return err
		}
		i.UserCache = cache
	}
	return nil
}

func (i *IDP) configureValidator() error {
	if i.PasswordValidator == nil {
		validator, err := LdapValidator()
		if err != nil {
			return err
		}
		i.PasswordValidator = validator
	}
	return nil
}

func (i *IDP) configureAttributeSources() error {
	if i.AttributeSources == nil {
		source, err := DefaultAttributeSource()
		if err != nil {
			return err
		}
		i.AttributeSources = []AttributeSource{source}
	}
	return nil
}

func (i *IDP) configureHandler() error {
	if i.Router == nil {
		i.Router = httprouter.New()
	}

	// Handle requests for metadata
	if i.MetadataHandler == nil {
		metadata, err := i.DefaultMetadataHandler()
		if err != nil {
			return err
		}
		i.MetadataHandler = metadata
	}
	// Handle artifact resolution
	if i.ArtifactResolveHandler == nil {
		i.ArtifactResolveHandler = i.DefaultArtifactResolveHandler()
	}
	// Handle artifact resolution
	if i.RedirectSLOHandler == nil {
		i.RedirectSLOHandler = i.DefaultRedirectSLOHandler()
	}
	// Handle redirect SSO requests
	if i.RedirectSSOHandler == nil {
		i.RedirectSSOHandler = i.DefaultRedirectSSOHandler()
	}

	// Handle ECP requests
	if i.ECPHandler == nil {
		i.ECPHandler = i.DefaultECPHandler()
	}

	// Handle password logins
	if i.PasswordLoginHandler == nil {
		i.PasswordLoginHandler = i.DefaultPasswordLoginHandler()
	}

	// Handle attribute query
	if i.QueryHandler == nil {
		i.QueryHandler = i.DefaultQueryHandler()
	}

	// Handle UI rendering
	if i.UIHandler == nil {
		i.UIHandler = ui.UI()
	}
	return nil
}

func (i *IDP) buildRoutes() error {
	r := i.Router
	r.HandlerFunc("GET", viper.GetString("metadata-path"), i.MetadataHandler)
	r.HandlerFunc("POST", viper.GetString("artifact-service-path"), i.ArtifactResolveHandler)
	r.HandlerFunc("GET", viper.GetString("slo-service-path"), i.RedirectSLOHandler)
	r.HandlerFunc("GET", viper.GetString("sso-service-path"), i.RedirectSSOHandler)
	r.HandlerFunc("POST", viper.GetString("ecp-service-path"), i.ECPHandler)
	r.HandlerFunc("POST", "/idp/static/login.html", i.PasswordLoginHandler)
	r.HandlerFunc("POST", viper.GetString("attribute-service-path"), i.QueryHandler)
	r.Handler("GET", "/idp/static/*path", i.UIHandler)
	r.Handler("GET", "/favicon.ico", i.UIHandler)
	return nil
}

func getIP(request *http.Request) net.IP {
	addr := request.RemoteAddr
	if strings.Contains(addr, ":") {
		addr = strings.Split(addr, ":")[0]
	}
	return net.ParseIP(addr)
}

func (i *IDP) setUserAttributes(user *model.User, req *model.AuthnRequest) error {
	for _, source := range i.AttributeSources {
		if err := source.AddAttributes(user, req); err != nil {
			return err
		}
	}
	return nil
}

func (i *IDP) buildAttributes(attrs map[string][]string) []*model.Attribute {
	attributes := make([]*model.Attribute, 0, len(attrs))
	for attrKey, attrValue := range attrs {
		attributes = append(attributes, &model.Attribute{Name: attrKey, Value: attrValue})
	}
	return attributes
}

func (i *IDP) LogoutPost(logoutReq *saml.LogoutRequest) []byte {
	tmpl := template.Must(template.New("saml-post-form").Parse(`` +
		`<form method="post" action="{{.URL}}" id="SAMLRequestForm">` +
		`<input type="hidden" name="logoutResponse" value="{{.LogoutResponse}}" />` +
		`<input id="SAMLSubmitButton" type="submit" value="Submit" />` +
		`</form>` +
		`<script>document.getElementById('SAMLSubmitButton').style.visibility="hidden";` +
		`document.getElementById('SAMLRequestForm').submit();</script>`))
	data := struct {
		URL            string
		LogoutResponse string
	}{
		LogoutResponse: logoutReq.LogoutResponse,
		URL:            logoutReq.SingleLogoutServiceUrl,
	}

	rv := bytes.Buffer{}
	if err := tmpl.Execute(&rv, data); err != nil {
		panic(err)
	}
	return rv.Bytes()
}
