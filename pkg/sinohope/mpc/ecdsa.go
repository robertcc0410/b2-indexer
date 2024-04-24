package mpc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

func Sign(private *ecdsa.PrivateKey, message string) (string, error) {
	messageBytes, err := hex.DecodeString(message)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(messageBytes)
	signature, err := ecdsa.SignASN1(rand.Reader, private, hash[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature), nil
}

func Verify(public *ecdsa.PublicKey, message, signature string) bool {
	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	messageBytes, err := hex.DecodeString(message)
	if err != nil {
		return false
	}
	hash := sha256.Sum256(messageBytes)
	return ecdsa.VerifyASN1(public, hash[:], signatureBytes)
}

func LoadTSSNodePublicKey(keyStr string) (*ecdsa.PublicKey, error) {
	keyStr = strings.ReplaceAll(keyStr, "\\n", "\n")
	pemData := []byte(keyStr)
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing the public key")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	pubKey, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}
	return pubKey, nil
}

func LoadKeypair(keyStr string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	keyStr = strings.ReplaceAll(keyStr, "\\n", "\n")
	load := func(keyStr string) (interface{}, error) {
		pemData := []byte(keyStr)
		var block *pem.Block
		for {
			block, pemData = pem.Decode(pemData)
			if block == nil {
				return nil, fmt.Errorf("failed to find PEM block containing the EC private key")
			}
			if block.Type == "EC PRIVATE KEY" {
				break
			}
		}

		priKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %v", err)
			}
			priKey, ok := keyInterface.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("not an ECDSA public key")
			}
			return priKey, nil
		}
		return priKey, nil
	}

	var err error
	var ok bool
	var privateKey *ecdsa.PrivateKey
	var result interface{}
	if result, err = load(keyStr); err != nil {
		return nil, nil, fmt.Errorf("failed to load private key: %v", err)
	}
	if privateKey, ok = result.(*ecdsa.PrivateKey); !ok {
		return nil, nil, fmt.Errorf("private key is not an ECDSA private key")
	}
	return privateKey, &privateKey.PublicKey, nil
}
