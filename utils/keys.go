package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// DecodeRSAPrivateKey decodes a PEM PKCS1 private key into a rsa.PrivateKey.
// NOTE: Public Key is automatically derived from the private key.
func DecodeRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// LoadRSAPrivateKeyFromFile reads a PEM PKCS1 private key file into a rsa.PrivateKey.
// NOTE: Public Key is automatically derived from the private key.
func LoadRSAPrivateKeyFromFile(path string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return DecodeRSAPrivateKey(data)
}

// DecodeRSAPublicKey decodes a PEM PKCS1 public key into a rsa.PublicKey.
func DecodeRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

// LoadRSAPublicKeyFromFile reads a PEM PKCS1 public key file into a rsa.PublicKey.
func LoadRSAPublicKeyFromFile(path string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return DecodeRSAPublicKey(data)
}

// LoadRSAKeyFromFile reads a PEM PKCS1 key pair (private and public key) into a rsa.PrivateKey
// with the PublicKey properly set to the given one, instead of the default deriving from
// the private key.
func LoadRSAKeyFromFile(privateKeyPath, publicKeyPath string) (*rsa.PrivateKey, error) {
	key, err := LoadRSAPrivateKeyFromFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	publicKey, err := LoadRSAPublicKeyFromFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	key.PublicKey = *publicKey
	return key, nil
}
