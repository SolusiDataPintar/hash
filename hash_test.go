package hash_test

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/SolusiDataPintar/hash"
	"github.com/stretchr/testify/require"
)

func TestHash(t *testing.T) {
	data := [][]byte{

		[]byte("abcdefghijklm"),
		[]byte("nopqrstuvwxyz"),
	}
	expected := "af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68"
	require.Equal(t, expected, hex.EncodeToString(hash.Hash(data...)))
}

func TestHashSingle(t *testing.T) {
	expected := "af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68"
	require.Equal(t, expected, hex.EncodeToString(hash.HashSingle([]byte("abcdefghijklmnopqrstuvwxyz"))))
}

func TestHashReader(t *testing.T) {
	f, err := os.Open("./test-file.jpg")
	require.NoError(t, err)
	defer f.Close()

	res, err := hash.HashReader(f)
	require.NoError(t, err)
	expected := "bef00c339d691ab98d1580bd42182bba5dde6b077d3a059344053d33add294bf034f7a66ab4ec06dd0255d12eab183ab36891b0addbb06942347e94dca650c3b"
	require.Equal(t, expected, hex.EncodeToString(res))
}

func TestHashFile(t *testing.T) {
	res, err := hash.HashFile("./test-file.jpg")
	require.NoError(t, err)
	expected := "bef00c339d691ab98d1580bd42182bba5dde6b077d3a059344053d33add294bf034f7a66ab4ec06dd0255d12eab183ab36891b0addbb06942347e94dca650c3b"
	require.Equal(t, expected, hex.EncodeToString(res))
}

func TestIsHashMatch(t *testing.T) {
	{ //test sha 3 512 match
		{
			bhash, err := hex.DecodeString("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68")
			require.NoError(t, err)
			require.True(t, hash.IsHashMatch([]byte("abcdefghijklmnopqrstuvwxyz"), bhash) == 0)
		}

		{
			bhash, err := hex.DecodeString("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca69")
			require.NoError(t, err)
			require.True(t, hash.IsHashMatch([]byte("abcdefghijklmnopqrstuvwxyz"), bhash) != 0)
		}
	}

	{ //test sha 2 256 match
		{
			bhash, err := hex.DecodeString("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
			require.NoError(t, err)
			require.True(t, hash.IsHashMatch([]byte("test"), bhash) == 0)
		}

		{
			bhash, err := hex.DecodeString("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a09")
			require.NoError(t, err)
			require.True(t, hash.IsHashMatch([]byte("test"), bhash) != 0)
		}
	}
}

func TestValidateHash(t *testing.T) {
	{
		bhash, err := hex.DecodeString("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68")
		require.NoError(t, err)
		require.NoError(t, hash.ValidateHash(bhash))
	}

	{
		bhash, err := hex.DecodeString("aaaaaf328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68")
		require.NoError(t, err)
		require.Error(t, hash.ValidateHash(bhash))
	}
}

func TestValidateHashString(t *testing.T) {
	require.NoError(t, hash.ValidateHashString("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68"))
	require.Error(t, hash.ValidateHashString("aaaaaf328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68"))
}

func TestSha256String(t *testing.T) {
	res, err := hash.Sha256String("test")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res)
	require.Equal(t, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", res)
}

func TestIsSha3512(t *testing.T) {
	{
		bhash, err := hex.DecodeString("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68")
		require.NoError(t, err)
		require.True(t, hash.IsSha3512(bhash))
	}

	{
		bhash, err := hex.DecodeString("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
		require.NoError(t, err)
		require.False(t, hash.IsSha3512(bhash))
	}
}

func TestIsSha3512Hex(t *testing.T) {
	require.True(t, hash.IsSha3512Hex("af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68"))
	require.False(t, hash.IsSha3512Hex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"))
	require.False(t, hash.IsSha3512Hex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08*^%$^&%^&^"))
}

func TestSha256Byte(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString("dGVzdA==")
	require.NoError(t, err)
	require.NotNil(t, data)
	require.NotEmpty(t, data)
	res, err := hash.Sha256Byte(data)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res)
	require.Equal(t, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", res)
}

func TestIsSHA256(t *testing.T) {
	res := hash.IsSHA256("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	require.Equal(t, true, res)

	res = hash.IsSHA256("abc")
	require.Equal(t, false, res)
}

func TestValidateSHA256(t *testing.T) {
	err := hash.ValidateSHA256("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	require.NoError(t, err)

	err = hash.ValidateSHA256("abc")
	require.Error(t, err)
	require.EqualError(t, err, "invalid hash:abc")
}
