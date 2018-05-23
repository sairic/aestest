package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"crypto/rand"
	"encoding/base64"
	"io"
)

var key = make([]byte, 32)

func init() {
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}
	fmt.Println("Generated AES 256 Key", base64.StdEncoding.EncodeToString(key))
}

func decrypt(ciphertext []byte, nonce []byte) (plaintext []byte, err error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return
}

func encrypt(plaintext []byte) (ciphertext []byte, nonce []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext = aesgcm.Seal(nil, nonce, plaintext, nil)
	return
}


func main() {
	ciphertext, nonce := encrypt([]byte("Ricardo"))
	plaintext, _ := decrypt(ciphertext, nonce)
	fmt.Println("Decrypted and got back", string(plaintext[:]))
}