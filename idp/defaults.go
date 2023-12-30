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
	"fmt"
	"github.com/spf13/viper"
)

func init() {
	viper.SetDefault("cookie-name", "idp-sess")
	viper.SetDefault("tls-certificate", "")
	viper.SetDefault("tls-private-key", "")
	viper.SetDefault("tls-ca", "")
	viper.SetDefault("listen-address", "127.0.0.1:9443")
	viper.SetDefault("server-name", "localhost:9443")
	viper.SetDefault("metadata-path", buildCompleteUrl("metadata"))
	viper.SetDefault("sso-service-path", buildCompleteUrl("SAML2/Redirect/SSO"))
	viper.SetDefault("slo-service-path", buildCompleteUrl("SAML2/Redirect/SLO"))
	viper.SetDefault("ecp-service-path", buildCompleteUrl("SAML2/SOAP/ECP"))
	viper.SetDefault("artifact-service-path", buildCompleteUrl("SAML2/SOAP/ArtifactResolution"))
	viper.SetDefault("attribute-service-path", buildCompleteUrl("SAML2/SOAP/AttributeQuery"))
	viper.SetDefault("temp-cache-duration", "5m")
	viper.SetDefault("user-cache-duration", "8h")
	viper.SetDefault("signature-algorithm", "")
	viper.SetDefault("digest-algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
	viper.SetDefault("saml-attribute-name-format", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
}

func buildCompleteUrl(subPath string) string {
	return fmt.Sprintf("/idp/%s", subPath)
}
