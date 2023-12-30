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
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/chriskery/sso-idp/model"
	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
)

func TestIDP_DefaultPasswordLoginHandler(t *testing.T) {
	i := &IDP{}
	ts := getTestIDP(t, i)
	defer ts.Close()
	// Need to cache request before attempting a login
	req := &model.AuthnRequest{
		ID: "2134",
	}
	data, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	i.TempCache.Set("1234", data)
	client := ts.Client()
	// Don't follow redirects. Want to see if we were going back to login form or not
	client.CheckRedirect = func(r *http.Request, old []*http.Request) error {
		return errors.New("no redirects allowed")
	}
	_, err = client.PostForm(ts.URL+"/ui/login.html", url.Values{"requestId": {"1234"}})
	assert.True(t, strings.Contains(err.Error(), "Invalid+login+or+password"), "login should have failed")
	if err == nil {
		t.Fatal("login should have failed")
	}
	assert.True(t, strings.Contains(err.Error(), "Invalid+login+or+password"), "login should have redirected to page with error")
}
