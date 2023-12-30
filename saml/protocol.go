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

package saml

import (
	"encoding/xml"
	"time"

	"github.com/amdonov/xmlsig"
)

type AuthnRequest struct {
	RequestAbstractType
	XMLName                       xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	AssertionConsumerServiceURL   string   `xml:",attr"`
	ProtocolBinding               string   `xml:",attr"`
	AssertionConsumerServiceIndex uint32   `xml:",attr"`
}

type LogoutRequest struct {
	RequestAbstractType
	XMLName                xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol LogoutRequest"`
	NotOnOrAfter           *time.Time `xml:",attr"`
	NameID                 *NameID
	SingleLogoutServiceUrl string `xml:",attr"`
	LogoutResponse         string `xml:",attr"`
	ProtocolBinding        string `xml:",attr"`
}

type ArtifactResolveEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    ArtifactResolveBody
}

type ArtifactResolveBody struct {
	XMLName         xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	ArtifactResolve ArtifactResolve
}

type ArtifactResolve struct {
	RequestAbstractType
	XMLName   xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResolve"`
	Artifact  string   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Artifact"`
	Signature *xmlsig.Signature
}

type ArtifactResponseEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    ArtifactResponseBody
}

type ArtifactResponseBody struct {
	XMLName          xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	ArtifactResponse ArtifactResponse
}

type ArtifactResponse struct {
	StatusResponseType
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol ArtifactResponse"`
	Response Response
}

type ECPResponseEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Header  ECPResponseHeader
	Body    ECPResponseBody
}

type ECPResponseHeader struct {
	XMLName                 xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Header"`
	ECPResponse             ECPResponse
	ECPRequestAuthenticated ECPRequestAuthenticated
}

type ECPResponse struct {
	XMLName                     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp Response"`
	Actor                       string   `xml:"http://schemas.xmlsoap.org/soap/envelope/ actor,attr"`
	MustUnderstand              int      `xml:"http://schemas.xmlsoap.org/soap/envelope/ mustUnderstand,attr"`
	AssertionConsumerServiceURL string   `xml:",attr"`
}

type ECPRequestAuthenticated struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp RequestAuthenticated"`
	Actor   string   `xml:"http://schemas.xmlsoap.org/soap/envelope/ actor,attr"`
}

type ECPResponseBody struct {
	XMLName  xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	Response Response
}

type Response struct {
	StatusResponseType
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	RawAssertion string   `xml:",innerxml"`
	Assertion    *Assertion
}

type Status struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode StatusCode
}

type StatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value   string   `xml:",attr"`
}

type RequestAbstractType struct {
	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Issuer       string    `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Destination  string    `xml:",attr"`
}

type StatusResponseType struct {
	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Issuer       *Issuer
	Destination  string `xml:",attr,omitempty"`
	InResponseTo string `xml:",attr"`
	Status       *Status
}

type SOAPFaultEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    SOAPFaultBody
}

type SOAPFaultBody struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	Fault   SOAPFault
}

type SOAPFault struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`
	Code    string   `xml:",faultcode"`
	String  string   `xml:",faultstring"`
}
