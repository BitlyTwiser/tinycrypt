# tinycrypt
Tiny library for encrypting files and byte streams

# Installation:
```go mod tidy```

# Testing:
- One can test the module via utilizing the go test framework.
```go test tinycrypt_test.go -v```

# Usage:
- Example usage can be seen within the test file.

```
package tinycrypt_test

import (
	. "github.com/BitlyTwiser/tinycrypt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenFile(t *testing.T) {
	t.Skip("Do not run else it will erase the file for testing due to the append nature of opening the file. This is present for either a generic test run or viewing functionality")
	badVal, fileData, _ := OpenFile("../IDoNotExist.txt")

	//We expect nil here as the file does not exist.
	assert.Nil(t, badVal)
	assert.Nil(t, fileData)

	existingVal, fileData, _ := OpenFile("./testing/testing_files/items.txt")

	if assert.NotNil(t, *existingVal) && assert.NotNil(t, *fileData) {
		t.Log("File exists properly")
	}
}

func TestFileEncrypt(t *testing.T) {
	enc := Encryption{FilePath: "./testing/testing_files/test.txt", SecureString: "Password123adar$"}

	err := enc.Encrypt()

	assert.Nil(t, err)
}

func TestFileDecrypt(t *testing.T) {
	enc := Encryption{FilePath: "./testing/testing_files/test.txt", SecureString: "Password123adar$"}

	err := enc.Decrypt()
	//Ensure that decryption does not fail.
	assert.Nil(t, err)
}

func TestPdfEncrypt(t *testing.T) {
	enc := Encryption{FilePath: "./testing/testing_files/test.pdf", SecureString: "Password123adar$"}

	err := enc.Encrypt()

	assert.Nil(t, err)
}

func TestPdfDecrypt(t *testing.T) {
	enc := Encryption{FilePath: "./testing/testing_files/test.pdf", SecureString: "Password123adar$"}

	err := enc.Decrypt()
	//Ensure that decryption does not fail.
	assert.Nil(t, err)
}

func TestBadFileType(t *testing.T) {
	enc := Encryption{FilePath: "./testing/testing_files/test", SecureString: "Password123adar$"}

	err := enc.Encrypt()

	assert.NotNil(t, err)
}

func TestEncryptAndDecryptOfFileStream(t *testing.T) {
	testingPass := "Password123adar$"
	t.Log("Testing Encryption of stream")
	words := []byte("Blue Red Green")

	stream, err := EncryptByteStream(testingPass, words)

	assert.NotNil(t, stream)
	assert.Nil(t, err)

	t.Logf("Encrypted Stream: %v", stream)

	t.Log("Testing Decryption of stream")

	decryptedStream, err := DecryptByteStream(testingPass, *stream)

	assert.Nil(t, err)
	assert.NotNil(t, decryptedStream)

	t.Logf("Decrypted String: %v", string(*decryptedStream))
}
```
