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

package cmd

import (
	"fmt"
	"github.com/chriskery/sso-idp/idp"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

var out io.Writer = os.Stdout // modified during testing

// serviceProviderCmd represents the serviceProvider command
var serviceProviderCmd = &cobra.Command{
	Use:   "service-provider metadata",
	Short: "add a service provider to the IdP",
	Long: `Parses the service provider's metadata to create an entry in the 
	configuration file.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		metadata, err := getReader(args[0])
		if err != nil {
			return err
		}
		defer metadata.Close()
		if err = idp.SaveSpFromMetadata(metadata); err != nil {
			return err
		}
		fmt.Fprintln(out, "Successfully added service provider from metadata", args[0])
		return nil
	},
}

func getReader(fileOrURL string) (io.ReadCloser, error) {
	url, err := url.Parse(fileOrURL)
	if err != nil {
		return nil, err
	}
	if url.IsAbs() {
		resp, err := http.Get(fileOrURL)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code, %d, when requesting metadata", resp.StatusCode)
		}
		return resp.Body, nil
	}
	// Just treat as a file
	return os.Open(fileOrURL)
}

func init() {
	AddCmd.AddCommand(serviceProviderCmd)
}
