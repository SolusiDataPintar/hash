package hash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"

	"golang.org/x/crypto/sha3"
)

const (
	_512hashlength     = 64
	sha256RegexString  = "^[A-Fa-f0-9]{64}$"
	sha3512RegexString = "^[A-Fa-f0-9]{128}$"
)

// Hash generates a SHA3 hash from input byte arrays.
func Hash(data ...[]byte) []byte {
	var hash [_512hashlength]byte
	if len(data) == 1 {
		hash = sha3.Sum512(data[0])
	} else {
		concatData := []byte{}
		for _, d := range data {
			concatData = append(concatData, d...)
		}
		hash = sha3.Sum512(concatData)
	}

	return hash[:]
}

func HashSingle(data []byte) []byte {
	hash := sha3.Sum512(data)
	return hash[:]
}

func HashReader(in io.Reader) ([]byte, error) {
	hasher := sha3.New512()
	_, err := io.Copy(hasher, in)
	return hasher.Sum(nil), err
}

func HashFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return HashReader(f)
}

func IsHashMatch(data, hash []byte) int {
	if IsSha3512(hash) {
		return isHashSha3512Match(data, hash)
	} else {
		return isHashSha2256Match(data, hash)
	}
}

func ValidateHash(hash []byte) error {
	if IsSha3512(hash) {
		return nil
	} else {
		return errors.New("invalid hash: " + hex.EncodeToString(hash))
	}
}

func ValidateHashString(hash string) error {
	if IsSha3512Hex(hash) {
		return nil
	} else {
		return errors.New("invalid hash string: " + hash)
	}
}

func IsSha3512(hash []byte) bool {
	return len(hash) == 64
}

func IsSha3512Hex(hash string) bool {
	regex := regexp.MustCompile(sha3512RegexString)
	return regex.MatchString(hash)
}

func isHashSha3512Match(data, hash []byte) int {
	dataHash := HashSingle(data)
	return bytes.Compare(dataHash, hash)
}

// Deprecated: In favor of sha3-512
func isHashSha2256Match(data, hash []byte) int {
	hasher := sha256.New()
	hasher.Write([]byte(data))
	dataHash := hasher.Sum(nil)
	return bytes.Compare(dataHash, hash)
}

// Deprecated: In favor of sha3-512
func Sha256String(value string) (string, error) {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(value))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Deprecated: In favor of sha3-512
func Sha256Byte(value []byte) (string, error) {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(value))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Deprecated: In favor of sha3-512
func IsSHA256(hash string) bool {
	regex := regexp.MustCompile(sha256RegexString)
	return regex.MatchString(hash)
}

// Deprecated: In favor of sha3-512
func ValidateSHA256(hash string) error {
	if IsSHA256(hash) {
		return nil
	} else {
		return errors.New("invalid hash:" + hash)
	}
}
