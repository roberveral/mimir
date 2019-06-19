package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
	"time"
)

const alphanumericCharset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seed = rand.New(
	rand.NewSource(time.Now().UnixNano()))

// RandStringWithCharset generates a random string of the given length
// using characters in the given charset.
func RandStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seed.Intn(len(charset))]
	}
	return string(b)
}

// RandString generates a random string of the given length using alphanumeric
// characters.
func RandString(length int) string {
	return RandStringWithCharset(length, alphanumericCharset)
}

// https://www.calhoun.io/creating-random-strings-in-go/

// GenerateSHA256 generates the Base64 URL Encoded SHA-256 hash of a given string.
func GenerateSHA256(s string) string {
	sha := sha256.Sum256([]byte(s))
	return base64.URLEncoding.EncodeToString(sha[:])
}

// GenerateSHA256NoPadding generates the Base64 URL Encoded SHA-256 hash of a given string with no padding.
func GenerateSHA256NoPadding(s string) string {
	sha := sha256.Sum256([]byte(s))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sha[:])
}
