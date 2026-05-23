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

	