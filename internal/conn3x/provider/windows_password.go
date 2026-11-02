// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/argon2"
)

// passwordHMAC is what state records for a password. A password is short and
// guessable, and the HMAC key often sits beside the state, so it goes through
// Argon2id first: each guess then costs time and memory, not one hash. The
// salt is secret, from the key, and differs for every host and account.
const passwordTag = "argon2id-"

func passwordHMAC(key []byte, id, password string) string {
	salt := hmac.New(sha256.New, key)
	salt.Write([]byte("conn3x password salt\x00" + id))
	stretched := argon2.IDKey([]byte(password), salt.Sum(nil), 2, 64*1024, 2, 32)
	// Tagged, so a later change of scheme can tell old values from new.
	return passwordTag + contentHMAC(key, id, "argon2id:"+hex.EncodeToString(stretched))
}
