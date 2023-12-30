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

package main

import (
	"context"
	"github.com/chriskery/sso-idp/idp"
	"github.com/gorilla/handlers"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func Test_initConfig(t *testing.T) {
	// make sure environment replacer is setup properly
	viper.SetDefault("my-config-value", "a")
	initConfig()
	assert.Equal(t, "a", viper.Get("my-config-value"), "initial value is wrong")
	os.Setenv("MY_CONFIG_VALUE", "b")
	assert.Equal(t, "b", viper.Get("my-config-value"), "second value is wrong")
}

func Test_server(t *testing.T) {
	initConfig()
	indentityProvider := &idp.IDP{}
	indentityProvider.EnableTLS = viper.GetBool("tls_enable")
	// Listen for shutdown signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	handler, err := indentityProvider.Handler()
	if err != nil {
		log.Fatalln(err)
	}

	server := &http.Server{
		Handler: handlers.CombinedLoggingHandler(os.Stdout, handler),
		Addr:    viper.GetString("listen-address"),
	}
	go func() {
		// Handle shutdown signal
		<-stop
		server.Shutdown(context.Background())
	}()

	log.Infof("listening for connections on %s", server.Addr)
	if indentityProvider.EnableTLS {
		server.TLSConfig = indentityProvider.TLSConfig
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	if err != http.ErrServerClosed {
		log.Fatalln(err)
	}
	log.Info("server shutdown cleanly")
}
