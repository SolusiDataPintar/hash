package hashpassword

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestDeriveKey(t *testing.T) {
	p := Parameter{
		Memory:      65536,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   64,
	}
	data := []byte("test")
	salt := []byte("salt")
	expected := "c40cdc7d182baeb1b57c163af0b09e19ed2ed2df1a98e3494c679eda1266ac575c01d1690885ff713fc9894d94e47979f1dce49d6138612e9b3ca9bb3a1595d0"

	result := DeriveKey(p, data, salt)

	if len(result) != 64 {
		t.Errorf("Expected length %d, got %d", len(expected), len(result))
	}

	if hex.EncodeToString(result) != expected {
		t.Errorf("Expected %s, got %s", expected, hex.EncodeToString(result))
	}
}

func TestEncode(t *testing.T) {
	p := Parameter{
		Memory:      65536,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   64,
	}
	salt := []byte("salt")
	hash := []byte("hash")

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	expected := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Hash)

	result := Encode(p, hash, salt)

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestHashPasswordAndValidatePassword(t *testing.T) {
	p := Parameter{
		Memory:      65536,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   64,
	}
	password := "test"

	hashed, err := HashPassword(p, password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !strings.HasPrefix(hashed, "$argon2id$") {
		t.Errorf("Expected hash to start with $argon2id$, got %s", hashed)
	}

	valid, err := ValidatePassword(password, hashed)
	if err != nil {
		t.Fatalf("ValidatePassword failed: %v", err)
	}
	if !valid {
		t.Errorf("Expected password to be valid, but it was not")
	}
}
