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
	"encoding/xml"
	"github.com/chriskery/sso-idp/model"
	"github.com/chriskery/sso-idp/saml"
	"net/http"
	"net/url"
	"time"

	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
)

// DefaultArtifactResolveHandler is the default implementation for the artifact resolution handler. It can be used as is, wrapped in other handlers, or replaced completely.
func (i *IDP) DefaultArtifactResolveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// We require transport authentication rather than message authentication
		tlsCert, err := getCertFromRequest(r)
		if err != nil {
			i.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		log.Infof("received artifact resolution request from %s", getSubjectDN(tlsCert.Subject))
		i.processArtifactResolutionRequest(w, r)
	}
}

func (i *IDP) processArtifactResolutionRequest(w http.ResponseWriter, r *http.Request) {
	decoder := xml.NewDecoder(r.Body)
	var resolveEnv saml.ArtifactResolveEnvelope
	err := decoder.Decode(&resolveEnv)
	// TODO confirm appropriate error response for this service
	if err != nil {
		i.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	artifact := resolveEnv.Body.ArtifactResolve.Artifact
	data, err := i.TempCache.Get(artifact)
	if err != nil {
		i.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	artifactResponse := &model.ArtifactResponse{}
	err = proto.Unmarshal(data, artifactResponse)
	// TODO confirm appropriate error response for this service
	if err != nil {
		i.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	response := i.makeAuthnResponse(artifactResponse.Request, artifactResponse.User)
	artResponseEnv := saml.ArtifactResponseEnvelope{
		Body: saml.ArtifactResponseBody{
			ArtifactResponse: saml.ArtifactResponse{
				StatusResponseType: saml.StatusResponseType{
					ID:           saml.NewID(),
					IssueInstant: now,
					InResponseTo: resolveEnv.Body.ArtifactResolve.ID,
					Version:      "2.0",
					Issuer:       saml.NewIssuer(i.entityID),
					Status: &saml.Status{
						StatusCode: saml.StatusCode{
							Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
						},
					},
				},
				Response: *response,
			},
		},
	}

	signature, err := i.signer.CreateSignature(response.Assertion)
	// TODO confirm appropriate error response for this service
	if err != nil {
		i.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response.Assertion.Signature = signature
	// TODO handle these errors. Probably can't do anything besides log, as we've already started to write the
	// response.
	_, err = w.Write([]byte(xml.Header))
	encoder := xml.NewEncoder(w)
	err = encoder.Encode(artResponseEnv)
	err = encoder.Flush()
}

func (i *IDP) sendArtifactResponse(authRequest *model.AuthnRequest, user *model.User,
	w http.ResponseWriter, r *http.Request) error {
	target, err := url.Parse(authRequest.AssertionConsumerServiceURL)
	if err != nil {
		i.Error(w, err.Error(), http.StatusInternalServerError)
	}
	parameters := url.Values{}
	artifact := getArtifact(i.entityID)
	// Store required data in the cache
	response := &model.ArtifactResponse{
		User:    user,
		Request: authRequest,
	}
	data, err := proto.Marshal(response)
	if err != nil {
		i.Error(w, err.Error(), http.StatusInternalServerError)
	}
	i.TempCache.Set(artifact, data)
	parameters.Add("SAMLart", artifact)
	parameters.Add("RelayState", authRequest.RelayState)
	target.RawQuery = parameters.Encode()
	// Don't send temporary redirect. We don't want the post resent
	http.Redirect(w, r, target.String(), http.StatusFound)

	return nil
}
