package utils

import (
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
