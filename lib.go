package cheatsheets

import (
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// get the type of encryption key.
func convertKeyToPEM(key interface{}) (string, error) {
	var keyType string
	var derBytes []byte

	switch key := key.(type) {
	case *rsa.PrivateKey:
		keyType = "RSA PRIVATE KEY"
		derBytes = x509.MarshalPKCS1PrivateKey(key)
	case *rsa.PublicKey:
		keyType = "RSA PUBLIC KEY"
		derBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", err
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: derBytes})), nil
	default:
		return "", fmt.Errorf("unsupported key type")
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: derBytes})), nil
}

// GenerateAesPair : generates private and public key.
func GenerateAesPair() (private string, public string, err error) {
	privateKey, err := rsa.GenerateKey(cryptoRand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	publicKey := &privateKey.PublicKey
	privateKeyStr, err := convertKeyToPEM(publicKey)
	if err != nil {
		return "", "", err
	}

	publicKeyStr, err := convertKeyToPEM(publicKey)
	if err != nil {
		return "", "", err
	}

	return privateKeyStr, publicKeyStr, nil
}
