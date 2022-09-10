package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
  "errors"
)

type Encrypter interface {
	Encrypt() error
	Decrypt() error
}

type void struct{}

type Encryption struct {
	FilePath     string
	SecureString string
}

var invalidFileHeaders []string = []string{"exe", "elf"}
var empty void

func OpenFile(FilePath string) (*os.File, *[]byte, error) {
	fileData, valid := ValidFile(FilePath)

	if !valid {
		log.Println("Invalid file!")

		return nil, nil, errors.New("Invalid File!")
	}

	file, err := os.OpenFile(FilePath, os.O_RDWR|os.O_TRUNC, os.ModeAppend)

	if err != nil {
		return nil, nil, err
	}

	return file, fileData, nil
}

func ValidFile(FilePath string) (*[]byte, bool) {
	file, err := os.ReadFile(FilePath)

	if err != nil {
		if os.IsNotExist(err) {
			log.Println("File not found! Nothing will be done..")

			return nil, false
		} else {
			log.Printf("Unknown Error while opening file.. Error: %v. Nothing will be done.", err.Error())

			return nil, false
		}
	}

	//Grab nibble to test for file header types
	nibble := strings.ToLower(string(file[1:4]))

	if contains(nibble, invalidFileHeaders) {
		log.Println("Cannot have this file type")

		return nil, false
	}

	return &file, true
}

func contains[V int | string | float64](searchVal V, searchArray []V) bool {
	set := make(map[V]void)

	for i := 0; i < len(searchArray); i++ {
		set[searchArray[i]] = empty
	}

	for k := range set {
		if k == searchVal {
			return true
		}
	}

	return false
}

func (e Encryption) Encrypt() error {
	file, fileData, err := OpenFile(e.FilePath)

	if err != nil {
		return err
	}

	defer file.Close()

	// WriteAt start writing bites to disk at designated offset. In this case, we replace the entire file with encrypted contents.
	encryptByteStream, err := encryptByteStream([]byte(*fileData), shaHash(e.SecureString))

	if err != nil {
		return err
	}
	_, err = file.WriteAt(*encryptByteStream, 0)

	if err != nil {
		return err
	}

	return nil
}

func (e Encryption) Decrypt() error {
	//Get fileData
	file, fileData, err := OpenFile(e.FilePath)

	if err != nil {
		return err
	}

	defer file.Close()

	decryptedByteStream, err := decryptData(hex.EncodeToString(*fileData), shaHash(e.SecureString))

	if err != nil {
		return err
	}

	_, err = file.WriteAt(*decryptedByteStream, 0)

	if err != nil {
		return err
	}

	return nil
}

func shaHash(hashValue string) string {
	v := sha256.New()
	v.Write([]byte(hashValue))

	return fmt.Sprintf("%x", v.Sum(nil))
}

func encryptByteStream(data []byte, secureString string) (*[]byte, error) {
	key, _ := hex.DecodeString(secureString)

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, data, nil)

	return &ciphertext, nil
}

// returns the decrypted file contents
// Returns Pointer to bytes array to avoid creating an objcet evertime we pass a value back.
func decryptData(data string, secureString string) (*[]byte, error) {
	key, _ := hex.DecodeString(secureString)
	dataDecoded, err := hex.DecodeString(data)

	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	nonce, ciphertext := dataDecoded[:aesgcm.NonceSize()], dataDecoded[aesgcm.NonceSize():]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		return nil, err
	}

	return &plaintext, nil
}

//Encrypt Byte Streams
func EncryptByteStream(pass string, stream []byte) (*[]byte, error) {
	encStream, err := encryptByteStream(stream, shaHash(pass))

	if err != nil {
		return nil, err
	}

	return encStream, nil
}

//Decrypt Byte Streams
func DecryptByteStream(pass string, stream []byte) (*[]byte, error) {
	decryptedByteStream, err := decryptData(hex.EncodeToString(stream), shaHash(pass))

	if err != nil {
		return nil, err
	}

	return decryptedByteStream, nil
}
