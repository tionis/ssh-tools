// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

//go:build !darwin

package prompt

import (
	"fmt"
	"log"

	"github.com/twpayne/go-pinentry-minimal/pinentry"
)

func GetPIN(serial uint32, retries int) (string, error) {
	client, err := pinentry.NewClient(
		pinentry.WithBinaryNameFromGnuPGAgentConf(),
		pinentry.WithGPGTTY(),
		pinentry.WithTitle("yubikey-agent PIN Prompt"),
		pinentry.WithDesc(fmt.Sprintf("YubiKey serial number: %d (%d tries remaining)", serial, retries)),
		pinentry.WithPrompt("Please enter your PIN:"),
		// Enable opt-in external PIN caching (in the OS keychain).
		// https://gist.github.com/mdeguzis/05d1f284f931223624834788da045c65#file-info-pinentry-L324
		pinentry.WithOption(pinentry.OptionAllowExternalPasswordCache),
		pinentry.WithKeyInfo(fmt.Sprintf("--yubikey-id-%d", serial)),
	)
	if err != nil {
		return "", err
	}
	defer func(client *pinentry.Client) {
		err := client.Close()
		if err != nil {
			log.Printf("failed to close pinentry client: %v", err)
		}
	}(client)

	pin, _, err := client.GetPIN()
	return pin, err
}
