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
	"compress/flate"
	"crypto"
	"crypto/dsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	"github.com/chriskery/sso-idp/model"
	"github.com/chriskery/sso-idp/saml"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

func (i *IDP) validateAuthRequest(request *saml.AuthnRequest, r *http.Request) error {
	// Only accept requests from registered service providers
	if request.Issuer == "" {
		return errors.New("request does not contain an issuer")
	}
	log.Infof("received authentication request from %s", request.Issuer)
	sp, ok := i.sps[request.Issuer]
	if !ok {
		return errors.New("request from an unregistered issuer")
	}
	// Determine the right assertion consumer service
	var acs *AssertionConsumerService
	for i, a := range sp.AssertionConsumerServices {
		// Find either the matching service or the default
		if a.Index == request.AssertionConsumerServiceIndex {
			acs = &sp.AssertionConsumerServices[i]
			break
		}
		if a.Location == request.AssertionConsumerServiceURL {
			acs = &sp.AssertionConsumerServices[i]
			break
		}
		if a.IsDefault {
			acs = &sp.AssertionConsumerServices[i]
		}
	}
	if acs == nil {
		return errors.New("unable to determine assertion consumer service")
	}
	// Don't allow a different URL than specified in the metadata
	if request.AssertionConsumerServiceURL == "" {
		request.AssertionConsumerServiceURL = acs.Location
	} else if request.AssertionConsumerServiceURL != acs.Location {
		return errors.New("assertion consumer location in request does not match metadata")
	}
	// At this point, we're OK with the request
	// Need to validate the signature
	// Have to use the raw query as pointed out in the spec.
	// https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
	// Line 621
	return verifySignature(r.URL.RawQuery, r.Form.Get("SigAlg"), r.Form.Get("Signature"), sp)
}

func (i *IDP) validateLogoutRequest(request *saml.LogoutRequest, r *http.Request) error {
	// Only accept requests from registered service providers
	if request.Issuer == "" {
		return errors.New("request does not contain an issuer")
	}
	log.Infof("received authentication request from %s", request.Issuer)
	sp, ok := i.sps[request.Issuer]
	if !ok {
		return errors.New("request from an unregistered issuer")
	}
	// Determine the right assertion consumer service
	if len(sp.SingleLogoutServices) == 0 {
		return errors.New("sp slo api not found")
	}
	slos := &sp.SingleLogoutServices[0]
	// Don't allow a different URL than specified in the metadata
	if request.SingleLogoutServiceUrl == "" {
		request.SingleLogoutServiceUrl = slos.Location
		request.ProtocolBinding = slos.Binding
	} else if request.SingleLogoutServiceUrl != slos.Location {
		return errors.New("slo in request does not match metadata")
	}
	return nil
}

func verifySignature(rawQuery, alg, expectedSig string, sp *ServiceProvider) error {
	// Split up the parts
	params := strings.Split(rawQuery, "&")
	pMap := make(map[string]string, len(params))
	for i := range params {
		parts := strings.Split(params[i], "=")
		if len(parts) != 2 {
			return errors.New("trouble validating signature on request")
		}
		pMap[parts[0]] = parts[1]
	}
	// Order them
	sigparts := []string{fmt.Sprintf("SAMLRequest=%s", pMap["SAMLRequest"])}
	if state, ok := pMap["RelayState"]; ok {
		sigparts = append(sigparts, fmt.Sprintf("RelayState=%s", state))
	}
	sigparts = append(sigparts, fmt.Sprintf("SigAlg=%s", pMap["SigAlg"]))
	sig := []byte(strings.Join(sigparts, "&"))
	// Validate the signature
	signature, err := base64.StdEncoding.DecodeString(expectedSig)
	if err != nil {
		return err
	}
	switch alg {
	case "http://www.w3.org/2009/xmldsig11#dsa-sha256":
		sum := sha256Sum(sig)
		return verifyDSA(sp, signature, sum)
	case "http://www.w3.org/2000/09/xmldsig#dsa-sha1":
		sum := sha1Sum(sig)
		return verifyDSA(sp, signature, sum)
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		sum := sha1Sum(sig)
		return rsa.VerifyPKCS1v15(sp.publicKey.(*rsa.PublicKey), crypto.SHA1, sum, signature)
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
		sum := sha256Sum(sig)
		return rsa.VerifyPKCS1v15(sp.publicKey.(*rsa.PublicKey), crypto.SHA256, sum, signature)
	default:
		return fmt.Errorf("unsupported signature algorithm, %s", alg)
	}
}

func verifyDSA(sp *ServiceProvider, signature, sum []byte) error {
	dsaSig := new(dsaSignature)
	if rest, err := asn1.Unmarshal(signature, dsaSig); err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("trailing data after DSA signature")
	}
	if dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
		return errors.New("DSA signature contained zero or negative values")
	}
	if !dsa.Verify(sp.publicKey.(*dsa.PublicKey), sum, dsaSig.R, dsaSig.S) {
		return errors.New("DSA verification failure")
	}
	return nil
}

func sha1Sum(sig []byte) []byte {
	h := sha1.New()
	h.Write(sig)
	return h.Sum(nil)
}

func sha256Sum(sig []byte) []byte {
	h := sha256.New()
	h.Write(sig)
	return h.Sum(nil)
}

// DefaultRedirectSSOHandler is the default implementation for the redirect login handler. It can be used as is, wrapped in other handlers, or replaced completely.
func (i *IDP) DefaultRedirectSSOHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := func() error {
			err := r.ParseForm()
			if err != nil {
				return err
			}
			relayState := r.Form.Get("RelayState")
			if len(relayState) > 80 {
				return errors.New("RelayState cannot be longer than 80 characters")
			}

			samlReq := r.Form.Get("SAMLRequest")
			// URL decoding is already performed
			// remove base64 encoding
			reqBytes, err := base64.StdEncoding.DecodeString(samlReq)
			if err != nil {
				return err
			}
			// Remove deflate
			req := flate.NewReader(bytes.NewReader(reqBytes))
			// Read the XML
			decoder := xml.NewDecoder(req)
			loginReq := &saml.AuthnRequest{}
			if err = decoder.Decode(loginReq); err != nil {
				return err
			}

			if err = i.validateAuthRequest(loginReq, r); err != nil {
				return err
			}

			// create saveable request
			saveableRequest, err := model.NewAuthnRequest(loginReq, relayState)
			if err != nil {
				return err
			}

			// check for existing session
			if user := i.getUserFromSession(r); user != nil {
				return i.respond(saveableRequest, user, w, r)
			}

			// check to see if they presented a client cert
			if user, err := i.loginWithCert(r, saveableRequest); user != nil {
				return i.respond(saveableRequest, user, w, r)
			} else if err != nil {
				return err
			}

			// need to display the login form
			data, err := proto.Marshal(saveableRequest)
			if err != nil {
				return err
			}
			id := uuid.New().String()
			err = i.TempCache.Set(id, data)
			if err != nil {
				return err
			}
			http.Redirect(w, r, fmt.Sprintf("/idp/static/login.html?requestId=%s",
				url.QueryEscape(id)), http.StatusTemporaryRedirect)
			return nil
		}()
		if err != nil {
			log.Error(err)
			i.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}

func (i *IDP) DefaultRedirectSLOHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := func() error {
			if err := r.ParseForm(); err != nil {
				return err
			}
			samlReq := r.Form.Get("SAMLRequest")
			// URL decoding is already performed
			// remove base64 encoding
			reqBytes, err := base64.StdEncoding.DecodeString(samlReq)
			if err != nil {
				return err
			}
			// Remove deflate
			req := flate.NewReader(bytes.NewReader(reqBytes))
			// Read the XML
			decoder := xml.NewDecoder(req)
			logoutReq := &saml.LogoutRequest{}
			if err = decoder.Decode(logoutReq); err != nil {
				return err
			}

			if err = i.validateLogoutRequest(logoutReq, r); err != nil {
				return err
			}

			i.deleteUserFromSession(r)

			http.SetCookie(w, &http.Cookie{
				Name:   i.cookieName,
				MaxAge: -1,
			})
			switch logoutReq.ProtocolBinding {
			case "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":
				w.Header().Add("Content-Security-Policy", ""+
					"default-src; "+
					"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
					"reflected-xss block; referrer no-referrer;")
				w.Header().Add("Content-type", "text/html")
				w.Write([]byte(`<!DOCTYPE html><html><body>`))
				w.Write(i.LogoutPost(logoutReq))
				w.Write([]byte(`</body></html>`))
			case "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect":
				http.Redirect(w, r, logoutReq.SingleLogoutServiceUrl, http.StatusFound)
			default:
				return errors.New("unsupported protocol binding")
			}
			return nil
		}()
		if err != nil {
			log.Error(err)
			i.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}

func (i *IDP) loginWithCert(r *http.Request, authnReq *model.AuthnRequest) (*model.User, error) {
	// check to see if they presented a client cert
	if clientCert, err := getCertFromRequest(r); err == nil {
		user := &model.User{
			Name:            getSubjectDN(clientCert.Subject),
			Format:          "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
			Context:         "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
			IP:              getIP(r).String(),
			X509Certificate: clientCert.Raw,
		}
		// Add attributes
		if err := i.setUserAttributes(user, authnReq); err != nil {
			return nil, err
		}
		i.Auditor.LogSuccess(user, authnReq, CertificateLogin)
		log.Infof("successful PKI login for %s", user.Name)
		return user, nil
	}
	return nil, nil
}

func (i *IDP) loginWithPasswordForm(r *http.Request, authnReq *model.AuthnRequest) (*model.User, error) {
	userName := r.Form.Get("username")
	attrs, err := i.PasswordValidator.Validate(userName, r.Form.Get("password"))
	if err != nil {
		log.Info(err)
		return nil, ErrInvalidPassword
	}
	//They have provided the right password
	user := &model.User{
		Name:       userName,
		Format:     "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
		Context:    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
		IP:         getIP(r).String(),
		Attributes: i.buildAttributes(attrs)}
	i.Auditor.LogSuccess(user, authnReq, PasswordLogin)
	log.Infof("successful password login for %s", user.Name)
	return user, nil
}

func (i *IDP) getUserFromSession(r *http.Request) *model.User {
	// check for cookie to see if user has a current session
	if cookie, err := r.Cookie(i.cookieName); err == nil {
		// Found a session cookie
		if data, err := i.UserCache.Get(cookie.Value); err == nil {
			// Cookie matched user in cache
			user := &model.User{}
			if err = proto.Unmarshal(data, user); err == nil {
				log.Infof("found existing session for %s", user.Name)
				return user
			}
		}
	}
	return nil
}

func (i *IDP) deleteUserFromSession(r *http.Request) {
	// check for cookie to see if user has a current session
	if cookie, err := r.Cookie(i.cookieName); err == nil {
		// Found a session cookie
		if _, err := i.UserCache.Get(cookie.Value); err == nil {
			_ = i.UserCache.Delete(cookie.Value)
			return
		}
	}
}

type dsaSignature struct {
	R, S *big.Int
}
