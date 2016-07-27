package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"encoding/base64"
)

func Encrypt(key, plaintext []byte) (ciphertext []byte, err error) {
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	ciphertext = make([]byte, aes.BlockSize+len(string(plaintext)))

	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader,iv); err != nil {
		return
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	ciphertext = []byte(base64.StdEncoding.EncodeToString(ciphertext))

	return
}

func Decrypt(key []byte, encryptedtext string) (plaintext []byte, err error) {
	var block cipher.Block
	var ciphertext []byte

	if ciphertext, err = base64.StdEncoding.DecodeString(encryptedtext); err != nil {
		return nil, err
	}
	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		err = errors.New("ciphertext too short")
		return
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	plaintext = ciphertext

	return

}