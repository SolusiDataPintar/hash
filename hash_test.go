package hash_test

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/SolusiDataPintar/hash"
)

func TestHash(t *testing.T) {
	data := [][]byte{

		[]byte("abcdefghijklm"),
		[]byte("nopqrstuvwxyz"),
	}
	expected := "af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68"
	if hex.EncodeToString(hash.Hash(data...)) != expected {
		t.Errorf("Expected %s, got %s", expected, hex.EncodeToString(hash.Hash(data...)))
	}
}

func TestHashSingle(t *testing.T) {
	expected := "af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68"
	if hex.EncodeToString(hash.HashSingle([]byte("abcdefghijklmnopqrstuvwxyz"))) != expected {
		t.Errorf("Expected %s, got %s", expected, hex.EncodeToString(hash.HashSingle([]byte("abcdefghijklmnopqrstuvwxyz"))))
	}
}

func TestHashReader(t *testing.T) {
	f, err := os.Open("./test-file.jpg")
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer f.Close()

	res, err := hash.HashReader(f)
	if err != nil {
		t.Fatalf("Failed to hash file: %v", err)
	}
	expected := "bef00c339d691ab98d1580bd42182bba5dde6b077d3a059344053d33add294bf034f7a66ab4ec06dd0255d12eab183ab36891b0addbb06942347e94dca650c3b"
	if hex.EncodeToString(res) != expected {
		t.Errorf("Expected %s, got %s", expected, hex.EncodeToString(res))
	}
}

func TestHashFile(t *testing.T) {
	res, err := hash.HashFile("./test-file.jpg")
	if err != nil {
		t.Fatalf("Failed to hash file: %v", err)
	}
	expected := "bef00c339d691ab98d1580bd42182bba5dde6b077d3a059344053d33add294bf034f7a66ab4ec06dd0255d12eab183ab36891b0addbb06942347e94dca650c3b"
	if hex.EncodeToString(res) != expected {
		t.Errorf("Expected %s, got %s", expected, hex.EncodeToString(res))
	}
}

func TestIsHashMatch(t *testing.T) {
	{ //test sha 3 512 match
		{
			bhash, err := hex.DecodeString("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68")
			if err != nil {
				t.Fatalf("Failed to decode hash: %v", err)
			}
			if hash.IsHashMatch([]byte("abcdefghijklmnopqrstuvwxyz"), bhash) != 0 {
				t.Errorf("Expected hash match to be 0, got %d", hash.IsHashMatch([]byte("abcdefghijklmnopqrstuvwxyz"), bhash))
			}
		}

		{
			bhash, err := hex.DecodeString("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca69")
			if err != nil {
				t.Fatalf("Failed to decode hash: %v", err)
			}
			if hash.IsHashMatch([]byte("abcdefghijklmnopqrstuvwxyz"), bhash) == 0 {
				t.Errorf("Expected hash match to be non-zero, got %d", hash.IsHashMatch([]byte("abcdefghijklmnopqrstuvwxyz"), bhash))
			}
		}
	}

	{ //test sha 2 256 match
		{
			bhash, err := hex.DecodeString("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
			if err != nil {
				t.Fatalf("Failed to decode hash: %v", err)
			}
			if hash.IsHashMatch([]byte("test"), bhash) != 0 {
				t.Errorf("Expected hash match to be 0, got %d", hash.IsHashMatch([]byte("test"), bhash))
			}
		}

		{
			bhash, err := hex.DecodeString("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a09")
			if err != nil {
				t.Fatalf("Failed to decode hash: %v", err)
			}
			if hash.IsHashMatch([]byte("test"), bhash) == 0 {
				t.Errorf("Expected hash match to be non-zero, got %d", hash.IsHashMatch([]byte("test"), bhash))
			}
		}
	}
}

func TestValidateHash(t *testing.T) {
	{
		bhash, err := hex.DecodeString("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68")
		if err != nil {
			t.Fatalf("Failed to decode hash: %v", err)
		}
		if err := hash.ValidateHash(bhash); err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	}

	{
		bhash, err := hex.DecodeString("aaaaaf328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68")
		if err != nil {
			t.Fatalf("Failed to decode hash: %v", err)
		}
		if err := hash.ValidateHash(bhash); err == nil {
			t.Error("Expected error, got nil")
		}
	}
}

func TestValidateHashString(t *testing.T) {
	if err := hash.ValidateHashString("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68"); err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if err := hash.ValidateHashString("aaaaaf328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68"); err == nil {
		t.Error("Expected error, got nil")
	}
}

func TestSha256String(t *testing.T) {
	res, err := hash.Sha256String("test")
	if err != nil {
		t.Fatalf("Failed to hash string: %v", err)
	}
	if res == "" {
		t.Fatal("Expected non-empty hash string, got empty")
	}
	if len(res) != 64 {
		t.Fatalf("Expected hash string length of 64, got %d", len(res))
	}
	if res != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("Expected hash string '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', got '%s'", res)
	}
}

func TestIsSha3512(t *testing.T) {
	{
		bhash, err := hex.DecodeString("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68")
		if err != nil {
			t.Fatalf("Failed to decode hash: %v", err)
		}
		if !hash.IsSha3512(bhash) {
			t.Error("Expected hash to be sha3-512, but it is not")
		}
	}

	{
		bhash, err := hex.DecodeString("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
		if err != nil {
			t.Fatalf("Failed to decode hash: %v", err)
		}
		if hash.IsSha3512(bhash) {
			t.Error("Expected hash to not be sha3-512, but it is")
		}
	}
}

func TestIsSha3512Hex(t *testing.T) {
	if !hash.IsSha3512Hex("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68") {
		t.Error("Expected true for valid sha3-512 hex string, got false")
	}
	if hash.IsSha3512Hex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08") {
		t.Error("Expected false for invalid sha3-512 hex string, got true")
	}
	if hash.IsSha3512Hex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08*^%$^&%^&^") {
		t.Error("Expected false for invalid sha3-512 hex string with special characters, got true")
	}
}

func TestSha256Byte(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString("dGVzdA==")
	if err != nil {
		t.Fatalf("Failed to decode base64 string: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Expected non-empty byte array, got empty")
	}
	res, err := hash.Sha256Byte(data)
	if err != nil {
		t.Fatalf("Failed to hash byte array: %v", err)
	}
	if res == "" {
		t.Fatal("Expected non-empty hash string, got empty")
	}
	if len(res) != 64 {
		t.Fatalf("Expected hash string length of 64, got %d", len(res))
	}
	if res != "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" {
		t.Fatalf("Expected hash string '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', got '%s'", res)
	}
}

func TestIsSHA256(t *testing.T) {
	if !hash.IsSHA256("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08") {
		t.Error("Expected true for valid SHA256 hash, got false")
	}

	if hash.IsSHA256("abc") {
		t.Error("Expected false for invalid SHA256 hash, got true")
	}
}

func TestValidateSHA256(t *testing.T) {
	err := hash.ValidateSHA256("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	err = hash.ValidateSHA256("abc")
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if err.Error() != "invalid hash:abc" {
		t.Errorf("Expected error 'invalid hash:abc', got '%v'", err)
	}
}
