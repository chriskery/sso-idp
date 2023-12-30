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
	"github.com/chriskery/sso-idp/model"
	"github.com/spf13/viper"
)

// AttributeSource allows implementations to retrieve user attributes from any upstream source such as a database, LDAP, or Web service.
type AttributeSource interface {
	AddAttributes(*model.User, *model.AuthnRequest) error
}

type simpleSource struct {
	users map[string][]*model.Attribute
}

// UserAttributes holds attributes for a given user
type UserAttributes struct {
	Name       string
	Attributes map[string][]string
}

func (ss *simpleSource) AddAttributes(user *model.User, _ *model.AuthnRequest) error {
	if atts, ok := ss.users[user.Name]; ok {
		user.AppendAttributes(atts)
	}
	return nil
}

// DefaultAttributeSource provides a default SAML attribute source that reads user information from the users key in the viper configuration
func DefaultAttributeSource() (AttributeSource, error) {
	userAttributes := []UserAttributes{}
	err := viper.UnmarshalKey("users", &userAttributes)
	if err != nil {
		return nil, err
	}
	users := make(map[string][]*model.Attribute)
	for i := range userAttributes {
		user := userAttributes[i]
		atts := []*model.Attribute{}
		for key, value := range user.Attributes {
			att := &model.Attribute{Name: key, Value: value}
			atts = append(atts, att)
		}
		users[user.Name] = atts
	}
	return &simpleSource{users}, nil
}
