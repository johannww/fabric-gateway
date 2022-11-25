/*
Copyright 2022 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package identity

import "crypto/ed25519"

func ed25519PrivateKeySign(privateKey ed25519.PrivateKey) Sign {
	return func(message []byte) ([]byte, error) {
		sig := ed25519.Sign(privateKey, message)
		return sig, nil
	}
}
