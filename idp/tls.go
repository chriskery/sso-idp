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
	"crypto/tls"
	"crypto/x509"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io/ioutil"
)

var (
	defaultX509Cert = []byte("-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCCQDDBt7ejDbQojANBgkqhkiG9w0BAQsFADAgMR4wHAYDVQQDDBVt\neXNlcnZpY2UuZXhhbXBsZS5jb20wHhcNMjIwNzE0MDMwNDIzWhcNMjMwNzE0MDMw\nNDIzWjAgMR4wHAYDVQQDDBVteXNlcnZpY2UuZXhhbXBsZS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8/dYQ0CjytSsglmfqupl9uLVfUeLq9lu0\ncMDQ81Sd/zjFAs2RXTo0C6P4m+V46uiXzpYrKBiaWB7QLnEJoXSv5RgJpGG98t85\nqfjyCViWQjK9oKCDYKfAdQqZywFH7IFVskDieV3NHHB/c6YHACoJa4GEq2+tE8pg\n8N/x9mdtiCRsuh6TrxpbEViA6Yk/5u9TENDNZ4WpSsFEQvmxOu2LmykRAq+P1/Y3\nYLMz8sWq1DdjOINV2yq/u/JdEMm6wvR6YHqQQUd/GEjigSAT7uKDzhMEAu3fCPcQ\nseHOTFfdAcywDh6L9rAZ/JOVAky7YeSWcLbMG/ormNhLa8qstJB/AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAClEv5YZAGk0r+tDqb1k1py3t26osZSRHROehKrTVIBK\ngoyN/ftQKAsK9a9i33hxNGPFiB1HrtyCEnIpgylR00C+C1fFBR2WVLffrPl7XV3I\n7HSJ9jABtyknaz+CuyEEdrhHRXb1SOG27cfuRiDkID3IheaSJYNuMQORBlrHtcA8\nkmTYuFp3GEm4BOOrxbssYHU5281VWZhwANOuVXN7HTMlDacg7NZt5L3kr/B/IEel\nCMtuB991hk5wvLKOc6QZdLo7p5qa10m0jZ7vywjHsi/H/gINQoqOPj1Zf8ghmu4Z\nDUYgu9BOsnLtk3e7pJtJ9CQYiN7A4jEbhhAqvPVEOGY=\n-----END CERTIFICATE-----\n")
	defaultX509Key  = []byte("-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC8/dYQ0CjytSsg\nlmfqupl9uLVfUeLq9lu0cMDQ81Sd/zjFAs2RXTo0C6P4m+V46uiXzpYrKBiaWB7Q\nLnEJoXSv5RgJpGG98t85qfjyCViWQjK9oKCDYKfAdQqZywFH7IFVskDieV3NHHB/\nc6YHACoJa4GEq2+tE8pg8N/x9mdtiCRsuh6TrxpbEViA6Yk/5u9TENDNZ4WpSsFE\nQvmxOu2LmykRAq+P1/Y3YLMz8sWq1DdjOINV2yq/u/JdEMm6wvR6YHqQQUd/GEji\ngSAT7uKDzhMEAu3fCPcQseHOTFfdAcywDh6L9rAZ/JOVAky7YeSWcLbMG/ormNhL\na8qstJB/AgMBAAECggEAJO6Z0YlMJzneJq0du5Ihgp8A2pK+/FmOTDGojGywwXtp\nlZ5Zm6mTQS5xKZkVe860C050rBRW0nqb8uTQdChYDDOBwgicjSkUFEmx+2J2LE7d\naY8lLudJgOOeYbV5F5wRHjUKVveOrBF9rnpkHIQcsuCOW+XAmhr+9ni72qXjSlT1\nbm5r7CSOYuxPd0EHV3GgIMHzCZ7XggVDMWpCs8o/5hMUcIEruunf6f9maidN12s2\nm563ehlv5zkjjgVjlROXBRCTRS8cHRdOAKkFthgvPviQKJvKxjgLlHkGCXvIyrAQ\nZaWGR4CA/sTZwNLIl/YJf4/0iyfiXEhBbFObvi/K8QKBgQDnHW+FaJFZiP0+2BHn\n4gIauu/DFJtMAxROIHoukxA7mWfpvvxK7hCZtUnOjdTOP0rYjNy5hlzj9b1f5QVO\nDmU+BAiA2+iOo7Kn3VnYfOFk9+kPYJSw3MwDrcl027Khvj/kkjyHAvIh37tOBhVH\nedpN9Hr6KWckhszJ3OpgGMRxWQKBgQDRV0o7P52Nf8UEBSRWI3JNOHrZPTpNa9RH\neFlaHl4c+yfdAKMkhntJUjq0kGof+8Gy+YNI55oPr5umkyGUNehLhxUlL33bGCKp\n6nzOMbCxwTqvTRQuDoPWAxaXExD175DuievRrtJLCfHI5Ju3drAd93bN3Sp1u5y/\nhe6dfn+9lwKBgBOwN0LnMJKvD9vdrlDRuRor2KcGx2AHVyB8tcvn7VcWb3rDMVz0\nwOdHQV1eScW0MJ0YCumnH5yv340exn/qzAcncs3/beVQ3rRcL/44TT87u1f7A0+5\nz4t0r5fL64DJ40mGh698ucHW/G7eJ8vp/oXrkNpk0ouTDDkaH8FF+t4pAoGAeXrt\nMcqt1CIUI0wUlQQG3XbsG0qjna/4RO069Mfwl2LL9Dzdb2G3A4p7VLMFUsAW3JRc\nsh7sUTP34Ec7UjWiMsoV5DlWEKFF5FKV0FYXkl9ufbH+BugXa0bpggvnaMB322Uf\n+tM3Z6JCs/CtyF5Qv2MOh1JTxHR19tJy8OQqnssCgYAHXF2cQUEGYYfoFj9sgSPH\ntOpH0/flTI/VvsryvSLcU0lTJORCKnawutqZ/Uufk64EZC1APVjk8Jv9ZOfT9XwK\nzrnsTXjpsHsjacXgmug87gQUU9XbVGIJS0ItI1gH64CYvGaiGkbzcocfhwczCGVf\nbk8fT6+oDWKhZHk/Jj5/aw==\n-----END PRIVATE KEY-----\n")
)

// ConfigureTLS not requiring users to present client certificates.
func ConfigureTLS() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(viper.GetString("tls-certificate"), viper.GetString("tls-private-key"))
	if err != nil {
		log.Errorf("tls-certificate not found ,use default tls cert:%s", err.Error())
		defaultCert, err := tls.X509KeyPair(defaultX509Cert, defaultX509Key)
		if err != nil {
			log.Error(err)
		}
		cert = defaultCert
	}
	ca := viper.GetString("tls-ca")

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		//Some but not all operations will require a client cert
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS12,
	}
	if ca != "" {
		caCert, err := ioutil.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
		tlsConfig.ClientCAs = caCertPool
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}
