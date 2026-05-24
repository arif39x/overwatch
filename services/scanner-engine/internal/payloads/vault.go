package payloads

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type Vault struct {
	Payloads map[string][]byte `json:"payloads"`
}

func Seal(inputDir string, outputFile string, key []byte) error {
	vault := Vault{
		Payloads: make(map[string][]byte),
	}
	
	data, _ := json.Marshal(vault)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return os.WriteFile(outputFile, ciphertext, 0644)
}

func Unseal(inputFile string, key []byte) (*Vault, error) {
	ciphertext, err := os.ReadFile(inputFile)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	var vault Vault
	err = json.Unmarshal(plaintext, &vault)
	return &vault, err
}
