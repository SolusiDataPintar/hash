package hashpassword

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/ccoveille/go-safecast"
	"golang.org/x/crypto/argon2"
)

func DeriveKey(p Parameter, data, salt []byte) []byte {
	return argon2.IDKey(data, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
}

func Encode(p Parameter, hashed, salt []byte) string {
	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hashed)

	// Return a string using the standard encoded hash representation.
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Hash)
}

func HashPassword(p Parameter, password string) (string, error) {
	// Generate a cryptographically secure random salt.
	salt, err := GenerateRandomBytes(p.SaltLength)
	if err != nil {
		return "", fmt.Errorf("generating random salt: %w", err)
	}

	// Pass the plaintext password, salt and parameters to the argon2.IDKey
	// function. This will generate a hash of the password using the Argon2id
	// variant.
	hashed := DeriveKey(p, []byte(password), salt)

	return Encode(p, hashed, salt), nil
}

func ValidatePassword(password, hashedPassword string) (bool, error) {
	// Extract the parameters, salt and derived key from the encoded password
	// hash.
	p, salt, hash, err := decodeHash(hashedPassword)
	if err != nil {
		return false, fmt.Errorf("decoding hash: %w", err)
	}

	// Derive the key from the other password using the same parameters.
	otherHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	// Check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	} else {
		return false, nil
	}
}

func decodeHash(encodedHash string) (p *Parameter, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, errors.New("the encoded hash is not in the correct format")
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, errors.New("incompatible version of argon2")
	}

	p = &Parameter{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding parameters: %w", err)
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding salt: %w", err)
	}

	p.SaltLength, err = safecast.ToUint32(len(salt))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("casting salt length: %w", err)
	}

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding hash: %w", err)
	}

	p.KeyLength, err = safecast.ToUint32(len(hash))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("casting key length: %w", err)
	}

	return p, salt, hash, nil
}

func GenerateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("generating random bytes: %w", err)
	}
	return b, nil
}
