package msnplus

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecryptPayloadWithSampleFixture(t *testing.T) {
	blob, err := GenerateSampleBlob(SamplePassword)
	require.NoError(t, err, "generate sample fixture")

	plaintext, err := DecryptPayload(blob, SamplePassword)
	require.NoError(t, err, "decrypt payload")

	expected, err := SampleHTML(SamplePassword)
	require.NoError(t, err, "render expected fixture")

	assert.Equal(t, expected, string(plaintext), "decrypted payload mismatch")
}

func TestFindPasswordInFileWithFixture(t *testing.T) {
	blob, err := GenerateSampleBlob(SamplePassword)
	require.NoError(t, err, "generate sample fixture")

	password, header, tried, err := FindPasswordInReader(blob, strings.NewReader("wrong\n"+SamplePassword+"\n"), nil)
	require.NoError(t, err, "find password")

	assert.Equal(t, SamplePassword, password, "unexpected password")
	assert.Equal(t, 2, tried, "unexpected tries")
	assert.Equal(t, uint16(0x0110), header.FileVersion, "unexpected file version")
}

func TestFindPasswordInFileReturnsNotFound(t *testing.T) {
	blob, err := GenerateSampleBlob(SamplePassword)
	require.NoError(t, err, "generate sample fixture")

	_, _, _, err = FindPasswordInReader(blob, strings.NewReader("wrong-one\nwrong-two\n"), nil)
	assert.True(t, errors.Is(err, ErrPasswordNotFound), "expected ErrPasswordNotFound, got %v", err)
}
