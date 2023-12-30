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
	"github.com/chriskery/sso-idp/cmd"
	"github.com/chriskery/sso-idp/idp"
	log "github.com/sirupsen/logrus"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "-idp",
	Short: "SAML 2 Identity Provider",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalln(err)
	}
}

func init() {
	log.SetReportCaller(true)
	cobra.OnInitialize(initConfig)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.SetConfigName("config")

	viper.AutomaticEnv() // read in environment variables that match
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	configPath := viper.GetString("config-path")
	if configPath != "" {
		viper.AddConfigPath(configPath)
	} else {
		viper.AddConfigPath("/etc/sso-idp")
		viper.AddConfigPath(".")
	}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Info("using config file:", viper.ConfigFileUsed())
	} else {
		log.Info("failed to load config file:", err)
	}
}

func main() {
	// This is a little different than cobra's typical main.
	// Moving this here makes it easier to embed lite-idp
	// and use its commands in other applications
	rootCmd.AddCommand(cmd.ServeCmd(&idp.IDP{}))
	rootCmd.AddCommand(cmd.AddCmd)
	rootCmd.AddCommand(cmd.HashCmd)
	rootCmd.AddCommand(cmd.ClusterCmd())
	Execute()
}
