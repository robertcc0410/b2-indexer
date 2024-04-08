package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
)

func RsaEncryptHex(originalData, publicKey string) (string, error) {
	decodePubKey, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", err
	}
	pubKey, parseErr := x509.ParsePKIXPublicKey(decodePubKey)
	if parseErr != nil {
		return "", parseErr
	}
	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey.(*rsa.PublicKey), []byte(originalData))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encryptedData), err
}

func RsaDecryptHex(encryptedData, privateKey string) (string, error) {
	encryptedDecodeBytes, err := hex.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	decodePrivKey, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", err
	}
	priKey, parseErr := x509.ParsePKCS8PrivateKey(decodePrivKey)
	if parseErr != nil {
		return "", parseErr
	}

	originalData, encryptErr := rsa.DecryptPKCS1v15(rand.Reader, priKey.(*rsa.PrivateKey), encryptedDecodeBytes)
	return string(originalData), encryptErr
}

func GenRsaKey(bits int) (privateKey, publicKey string, err error) {
	priKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}

	derStream, err := x509.MarshalPKCS8PrivateKey(priKey)
	if err != nil {
		return "", "", err
	}
	puKey := &priKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(puKey)
	if err != nil {
		return "", "", err
	}

	privateKey = hex.EncodeToString(derStream)
	publicKey = hex.EncodeToString(derPkix)
	return
}
