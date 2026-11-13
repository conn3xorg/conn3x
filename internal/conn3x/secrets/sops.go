// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

// Package secrets reads SOPS files encrypted with age, the format teams
// commit secrets in. It reads only: writing and re-keying are sops's job.
//
// A SOPS file keeps its keys readable and each value encrypted with
// AES-256-GCM under one data key, with the value's path as additional
// data. The data key is wrapped once per recipient in the file's sops
// block, beside a MAC: a SHA-512 over the plaintext values in document
// order, encrypted under the data key with the file's lastmodified time as
// additional data. Reading checks the MAC, so a value changed without the
// key fails loudly.
package secrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"gopkg.in/yaml.v3"
)

// macOnlyEncryptedInit starts the MAC of a file with mac_only_encrypted set,
// as sops does, so the two kinds of MAC never match each other.
var macOnlyEncryptedInit = []byte{0x8a, 0x3f, 0xd2, 0xad, 0x54, 0xce, 0x66, 0x52, 0x7b, 0x10, 0x34, 0xf3, 0xd1, 0x47, 0xbe, 0xb, 0xb, 0x97, 0x5b, 0x3b, 0xf4, 0x4f, 0x72, 0xc6, 0xfd, 0xad, 0xec, 0x81, 0x76, 0xf2, 0x7d, 0x69}

var encRe = regexp.MustCompile(`^ENC\[AES256_GCM,data:(.*),iv:(.+),tag:(.+),type:(.+)\]$`)

// metadata is the sops block, as far as reading needs it.
type metadata struct {
	Age []struct {
		Recipient string `yaml:"recipient"`
		Enc       string `yaml:"enc"`
	} `yaml:"age"`
	LastModified            string `yaml:"lastmodified"`
	MAC                     string `yaml:"mac"`
	UnencryptedSuffix       string `yaml:"unencrypted_suffix"`
	EncryptedSuffix         string `yaml:"encrypted_suffix"`
	UnencryptedRegex        string `yaml:"unencrypted_regex"`
	EncryptedRegex          string `yaml:"encrypted_regex"`
	UnencryptedCommentRegex string `yaml:"unencrypted_comment_regex"`
	EncryptedCommentRegex   string `yaml:"encrypted_comment_regex"`
	MACOnlyEncrypted        bool   `yaml:"mac_only_encrypted"`
}

// Identities finds the age keys sops would: SOPS_AGE_KEY, the file
// SOPS_AGE_KEY_FILE names, and sops/age/keys.txt in the user's config
// directory. A file that isn't there is passed over.
func Identities() ([]age.Identity, error) {
	var out []age.Identity
	add := func(src, text string) error {
		ids, err := age.ParseIdentities(strings.NewReader(text))
		if err != nil {
			return fmt.Errorf("reading age keys from %s: %w", src, err)
		}
		out = append(out, ids...)
		return nil
	}
	if k := os.Getenv("SOPS_AGE_KEY"); k != "" {
		if err := add("SOPS_AGE_KEY", k); err != nil {
			return nil, err
		}
	}
	var files []string
	if f := os.Getenv("SOPS_AGE_KEY_FILE"); f != "" {
		files = append(files, f)
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		dir, _ = os.UserConfigDir()
	}
	if dir != "" {
		files = append(files, filepath.Join(dir, "sops", "age", "keys.txt"))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := add(f, string(raw)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Decrypt reads a SOPS file, YAML or JSON, and returns its values by path:
// top-level keys as written, nested ones joined with dots, list items by
// index. Values are strings, as written in the file.
func Decrypt(src []byte, ids []age.Identity) (map[string]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, fmt.Errorf("not YAML or JSON: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("a SOPS file is a mapping at the top level")
	}
	root := doc.Content[0]
	var meta *metadata
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "sops" {
			meta = &metadata{}
			if err := root.Content[i+1].Decode(meta); err != nil {
				return nil, fmt.Errorf("reading the sops block: %w", err)
			}
		}
	}
	if meta == nil {
		return nil, errors.New("there's no sops block, so it isn't a SOPS file; encrypt it with sops")
	}
	if meta.UnencryptedCommentRegex != "" || meta.EncryptedCommentRegex != "" {
		return nil, errors.New("it chooses what to encrypt by comment, with encrypted_comment_regex or unencrypted_comment_regex, which Conn3x can't read yet")
	}
	if len(meta.Age) == 0 {
		return nil, errors.New("it has no age recipient; Conn3x reads SOPS files encrypted to age keys")
	}
	if len(ids) == 0 {
		return nil, errors.New("no age key found: set SOPS_AGE_KEY or SOPS_AGE_KEY_FILE, or put one in sops/age/keys.txt in your config directory, as sops does")
	}
	key, err := dataKey(meta, ids)
	if err != nil {
		return nil, err
	}

	r := reader{meta: meta, key: key, out: map[string]string{}, hash: sha512.New()}
	if meta.MACOnlyEncrypted {
		r.hash.Write(macOnlyEncryptedInit)
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if k := root.Content[i].Value; k != "sops" {
			if err := r.walk(root.Content[i+1], []string{k}, []string{k}); err != nil {
				return nil, err
			}
		}
	}
	mac := fmt.Sprintf("%X", r.hash.Sum(nil))
	stamp := meta.LastModified
	if t, err := time.Parse(time.RFC3339, stamp); err == nil {
		stamp = t.Format(time.RFC3339)
	}
	want, _, err := r.decrypt(meta.MAC, stamp)
	if err != nil {
		return nil, fmt.Errorf("reading its MAC: %w", err)
	}
	if want != mac {
		return nil, errors.New("its MAC doesn't match its values: the file was changed without its key")
	}
	return r.out, nil
}

// dataKey unwraps the data key with whichever identity a recipient has.
func dataKey(meta *metadata, ids []age.Identity) ([]byte, error) {
	var last error
	for _, a := range meta.Age {
		rd, err := age.Decrypt(armor.NewReader(strings.NewReader(a.Enc)), ids...)
		if err != nil {
			last = err
			continue
		}
		key, err := io.ReadAll(rd)
		if err != nil {
			return nil, err
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("its data key is %d bytes, not 32", len(key))
		}
		return key, nil
	}
	var none *age.NoIdentityMatchError
	if errors.As(last, &none) {
		return nil, errors.New("none of your age keys is one of its recipients")
	}
	return nil, fmt.Errorf("unwrapping its data key: %w", last)
}

type reader struct {
	meta *metadata
	key  []byte
	out  map[string]string
	hash hash.Hash
}

// walk visits values in document order, as sops does. path is what the
// values were encrypted under: a list item shares its list's. name is the
// key in the result, with list indexes.
func (r *reader) walk(n *yaml.Node, path, name []string) error {
	switch n.Kind {
	case yaml.AliasNode:
		return errors.New("it uses a YAML alias, which sops doesn't write")
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if err := r.walk(n.Content[i+1], append(path, k), append(name, k)); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, item := range n.Content {
			if err := r.walk(item, path, append(name, strconv.Itoa(i))); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		return r.leaf(n, path, name)
	}
	return nil
}

func (r *reader) leaf(n *yaml.Node, path, name []string) error {
	key := strings.Join(name, ".")
	if !r.encrypted(path) {
		var v any
		if err := n.Decode(&v); err != nil {
			return err
		}
		if v == nil {
			return nil // sops neither hashes nor keeps a null
		}
		b, err := toBytes(v)
		if err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		if !r.meta.MACOnlyEncrypted {
			r.hash.Write(b)
		}
		r.out[key] = string(b)
		if bv, ok := v.(bool); ok {
			r.out[key] = strconv.FormatBool(bv)
		}
		return nil
	}
	plain, typ, err := r.decrypt(n.Value, strings.Join(path, ":")+":")
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	v, err := typed(plain, typ)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	b, err := toBytes(v)
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	r.hash.Write(b)
	r.out[key] = plain
	if bv, ok := v.(bool); ok {
		r.out[key] = strconv.FormatBool(bv)
	}
	return nil
}

// typed is a decrypted value as the type sops recorded, which is what it
// hashed.
func typed(plain, typ string) (any, error) {
	switch typ {
	case "str", "bytes", "comment":
		return plain, nil
	case "int":
		return strconv.Atoi(plain)
	case "float":
		return strconv.ParseFloat(plain, 64)
	case "bool":
		return strconv.ParseBool(plain)
	case "time":
		var t time.Time
		err := t.UnmarshalText([]byte(plain))
		return t, err
	}
	return nil, fmt.Errorf("its encrypted value has type %q, which Conn3x can't read", typ)
}

// decrypt opens one ENC[...] value, and returns its plaintext and the type
// sops recorded for it.
func (r *reader) decrypt(value, aad string) (string, string, error) {
	if value == "" {
		return "", "str", nil // sops writes an empty value as it is
	}
	m := encRe.FindStringSubmatch(value)
	if m == nil {
		return "", "", errors.New("isn't encrypted, though the file says it should be")
	}
	var parts [3][]byte
	for i := range parts {
		b, err := base64.StdEncoding.DecodeString(m[i+1])
		if err != nil {
			return "", "", fmt.Errorf("its encrypted value isn't base64: %w", err)
		}
		parts[i] = b
	}
	block, err := aes.NewCipher(r.key)
	if err != nil {
		return "", "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(parts[1]))
	if err != nil {
		return "", "", err
	}
	plain, err := gcm.Open(nil, parts[1], append(parts[0], parts[2]...), []byte(aad))
	if err != nil {
		return "", "", errors.New("doesn't decrypt: the file was changed, or moved between keys, without sops")
	}
	return string(plain), m[4], nil
}

// encrypted says, from the file's own rules, whether sops encrypted the
// values under path.
func (r *reader) encrypted(path []string) bool {
	m := r.meta
	enc := true
	if m.UnencryptedSuffix != "" {
		for _, p := range path {
			if strings.HasSuffix(p, m.UnencryptedSuffix) {
				enc = false
				break
			}
		}
	}
	if m.EncryptedSuffix != "" {
		enc = false
		for _, p := range path {
			if strings.HasSuffix(p, m.EncryptedSuffix) {
				enc = true
				break
			}
		}
	}
	if m.UnencryptedRegex != "" {
		for _, p := range path {
			if ok, _ := regexp.MatchString(m.UnencryptedRegex, p); ok {
				enc = false
				break
			}
		}
	}
	if m.EncryptedRegex != "" {
		enc = false
		for _, p := range path {
			if ok, _ := regexp.MatchString(m.EncryptedRegex, p); ok {
				enc = true
				break
			}
		}
	}
	return enc
}

// toBytes is sops's ToBytes, for the values it left unencrypted.
func toBytes(v any) ([]byte, error) {
	switch v := v.(type) {
	case string:
		return []byte(v), nil
	case int:
		return []byte(strconv.Itoa(v)), nil
	case float64:
		return []byte(strconv.FormatFloat(v, 'f', -1, 64)), nil
	case bool:
		if v {
			return []byte("True"), nil
		}
		return []byte("False"), nil
	case time.Time:
		return v.MarshalText()
	}
	return nil, fmt.Errorf("an unencrypted value of type %T, which Conn3x can't read", v)
}

// ReadFile decrypts the SOPS file at path with the age keys sops would use.
func ReadFile(path string) (map[string]string, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ids, err := Identities()
	if err != nil {
		return nil, err
	}
	out, err := Decrypt(bytes.TrimPrefix(src, []byte("\xef\xbb\xbf")), ids)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}
