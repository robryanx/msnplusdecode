package msnplus

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecryptDirectoryWritesDecodedFiles(t *testing.T) {
	t.Parallel()

	sampleBlob, err := GenerateSampleBlob(SamplePassword)
	require.NoError(t, err, "generate sample fixture")

	input := fstest.MapFS{
		"nested/" + SamplePLEFilename: &fstest.MapFile{Data: sampleBlob, Mode: fs.ModePerm},
		"nested/ignore.txt":           &fstest.MapFile{Data: []byte("ignore"), Mode: fs.ModePerm},
	}
	output := newMemoryOutputFS()

	stats, err := decryptDirectoryFS(input, output, SamplePassword, nil)
	require.NoError(t, err, "decrypt directory")
	assert.Equal(t, DecodeDirectoryStats{Processed: 1, Wrote: 1, Skipped: 0, Failed: 0}, stats, "unexpected stats")

	got, exists := output.files["nested/sample_known_password.txt"]
	require.True(t, exists, "decoded output should exist")
	expected, err := SampleHTML(SamplePassword)
	require.NoError(t, err, "render expected fixture")
	assert.Equal(t, expected, string(got), "decoded output mismatch")
}

func TestDecryptDirectorySkipsExistingFiles(t *testing.T) {
	t.Parallel()

	sampleBlob, err := GenerateSampleBlob(SamplePassword)
	require.NoError(t, err, "generate sample fixture")

	input := fstest.MapFS{
		SamplePLEFilename: &fstest.MapFile{Data: sampleBlob, Mode: fs.ModePerm},
	}
	output := newMemoryOutputFS()
	output.files["sample_known_password.txt"] = []byte("existing")

	var logs []string
	stats, err := decryptDirectoryFS(input, output, SamplePassword, func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})
	require.NoError(t, err, "decrypt directory")
	assert.Equal(t, DecodeDirectoryStats{Processed: 1, Wrote: 0, Skipped: 1, Failed: 0}, stats, "unexpected stats")

	got := output.files["sample_known_password.txt"]
	assert.Equal(t, "existing", string(got), "existing output should be preserved")
	require.Len(t, logs, 1, "unexpected logs")
	assert.True(t, strings.Contains(logs[0], "skip existing:"), "unexpected logs: %v", logs)
}

func TestDecryptDirectoryContinuesOnPasswordCheckFailure(t *testing.T) {
	t.Parallel()

	goodBlob, err := GenerateSampleBlob(SamplePassword)
	require.NoError(t, err, "generate valid sample fixture")

	badBlob, err := GenerateSampleBlob("wrong-password")
	require.NoError(t, err, "generate invalid sample fixture")

	input := fstest.MapFS{
		"good/" + SamplePLEFilename: &fstest.MapFile{Data: goodBlob, Mode: fs.ModePerm},
		"bad/bad.ple":               &fstest.MapFile{Data: badBlob, Mode: fs.ModePerm},
	}
	output := newMemoryOutputFS()

	var logs []string
	stats, err := decryptDirectoryFS(input, output, SamplePassword, func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	})
	require.NoError(t, err, "decrypt directory")
	assert.Equal(t, DecodeDirectoryStats{Processed: 2, Wrote: 1, Skipped: 0, Failed: 1}, stats, "unexpected stats")
	assert.Contains(t, output.files, "good/sample_known_password.txt")
	assert.NotContains(t, output.files, "bad/bad.txt")
	require.Len(t, logs, 2, "unexpected logs")
	assert.Contains(t, logs, "password check failed: bad/bad.ple")
	assert.Contains(t, logs, "wrote: good/sample_known_password.txt")
}

type memoryOutputFS struct {
	files map[string][]byte
}

func newMemoryOutputFS() *memoryOutputFS {
	return &memoryOutputFS{files: make(map[string][]byte)}
}

func (m *memoryOutputFS) Exists(path string) (bool, error) {
	_, ok := m.files[path]
	return ok, nil
}

func (m *memoryOutputFS) WriteFile(path string, data []byte) error {
	m.files[path] = append([]byte(nil), data...)
	return nil
}

func (m *memoryOutputFS) DisplayPath(path string) string {
	return path
}
