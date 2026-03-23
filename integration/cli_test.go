package integration_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/robryanx/msnplusdecode/internal/msnplus"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindPasswordCLI(t *testing.T) {
	t.Parallel()

	rootDir := repoRoot(t)
	tempDir := t.TempDir()

	sampleBlob, err := msnplus.GenerateSampleBlob(msnplus.SamplePassword)
	require.NoError(t, err)

	inputPath := filepath.Join(tempDir, msnplus.SamplePLEFilename)
	passwordFile := filepath.Join(tempDir, "passwords.txt")

	err = os.WriteFile(inputPath, sampleBlob, 0o644)
	require.NoError(t, err)
	err = os.WriteFile(passwordFile, []byte("wrong\n"+msnplus.SamplePassword+"\n"), 0o644)
	require.NoError(t, err)

	stdout, stderr, err := runGoCLI(t, rootDir, "./cmd/find-password", "--password-file", passwordFile, inputPath)
	require.NoError(t, err, "stderr=%s", stderr)

	assert.Contains(t, stdout, "found: "+msnplus.SamplePassword)
	assert.Contains(t, stdout, "file_version=0x0110")
	assert.Contains(t, stdout, "encoding_flag=1")
	assert.Contains(t, stdout, "encrypted_check_len=13")
	assert.Contains(t, stdout, "payload_offset=0x1f")
	assert.Empty(t, stderr)
}

func TestFindPasswordCLIGeneratesSample(t *testing.T) {
	t.Parallel()

	rootDir := repoRoot(t)
	samplePath := filepath.Join(rootDir, "testdata", msnplus.SamplePLEFilename)

	original, err := os.ReadFile(samplePath)
	require.NoError(t, err)
	t.Cleanup(func() {
		restoreErr := os.WriteFile(samplePath, original, 0o644)
		require.NoError(t, restoreErr)
	})

	expected, err := msnplus.GenerateSampleBlob(msnplus.SamplePassword)
	require.NoError(t, err)

	stdout, stderr, err := runGoCLI(t, rootDir, "./cmd/find-password", "--generate-sample")
	require.NoError(t, err, "stderr=%s", stderr)

	got, err := os.ReadFile(samplePath)
	require.NoError(t, err)

	assert.Equal(t, expected, got)
	assert.Contains(t, stdout, `wrote sample file testdata/`+msnplus.SamplePLEFilename+` with password "`+msnplus.SamplePassword+`"`)
	assert.Empty(t, stderr)
}

func TestDecodeDirCLIWritesFiles(t *testing.T) {
	t.Parallel()

	rootDir := repoRoot(t)
	tempDir := t.TempDir()

	sampleBlob, err := msnplus.GenerateSampleBlob(msnplus.SamplePassword)
	require.NoError(t, err)

	inputDir := filepath.Join(tempDir, "input")
	outputDir := filepath.Join(tempDir, "output")
	inputPath := filepath.Join(inputDir, "nested", msnplus.SamplePLEFilename)

	err = os.MkdirAll(filepath.Dir(inputPath), 0o755)
	require.NoError(t, err)
	err = os.WriteFile(inputPath, sampleBlob, 0o644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(inputDir, "nested", "ignore.txt"), []byte("ignore"), 0o644)
	require.NoError(t, err)

	stdout, stderr, err := runGoCLI(t, rootDir, "./cmd/decode-dir", "--password", msnplus.SamplePassword, "--output-dir", outputDir, inputDir)
	require.NoError(t, err, "stderr=%s", stderr)

	outputPath := filepath.Join(outputDir, "nested", "sample_known_password.txt")
	got, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	expected, err := msnplus.SampleHTML(msnplus.SamplePassword)
	require.NoError(t, err)

	assert.Equal(t, expected, string(got))
	assert.Contains(t, stdout, "wrote: "+outputPath)
	assert.Contains(t, stdout, "processed=1 wrote=1 skipped=0 failed=0")
	assert.Empty(t, stderr)
}

func TestDecodeDirCLISkipsExistingFiles(t *testing.T) {
	t.Parallel()

	rootDir := repoRoot(t)
	tempDir := t.TempDir()

	sampleBlob, err := msnplus.GenerateSampleBlob(msnplus.SamplePassword)
	require.NoError(t, err)

	inputDir := filepath.Join(tempDir, "input")
	outputDir := filepath.Join(tempDir, "output")
	inputPath := filepath.Join(inputDir, msnplus.SamplePLEFilename)
	outputPath := filepath.Join(outputDir, "sample_known_password.txt")

	err = os.MkdirAll(filepath.Dir(inputPath), 0o755)
	require.NoError(t, err)
	err = os.WriteFile(inputPath, sampleBlob, 0o644)
	require.NoError(t, err)
	err = os.MkdirAll(filepath.Dir(outputPath), 0o755)
	require.NoError(t, err)
	err = os.WriteFile(outputPath, []byte("existing"), 0o644)
	require.NoError(t, err)

	stdout, stderr, err := runGoCLI(t, rootDir, "./cmd/decode-dir", "--password", msnplus.SamplePassword, "--output-dir", outputDir, inputDir)
	require.NoError(t, err, "stderr=%s", stderr)

	got, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	assert.Equal(t, "existing", string(got))
	assert.Contains(t, stdout, "skip existing: "+outputPath)
	assert.Contains(t, stdout, "processed=1 wrote=0 skipped=1 failed=0")
	assert.Empty(t, stderr)
}

func TestDecodeDirCLIContinuesOnPasswordCheckFailure(t *testing.T) {
	t.Parallel()

	rootDir := repoRoot(t)
	tempDir := t.TempDir()

	goodBlob, err := msnplus.GenerateSampleBlob(msnplus.SamplePassword)
	require.NoError(t, err)
	badBlob, err := msnplus.GenerateSampleBlob("wrong-password")
	require.NoError(t, err)

	inputDir := filepath.Join(tempDir, "input")
	outputDir := filepath.Join(tempDir, "output")
	goodInputPath := filepath.Join(inputDir, "good", msnplus.SamplePLEFilename)
	badInputPath := filepath.Join(inputDir, "bad", "bad.ple")
	goodOutputPath := filepath.Join(outputDir, "good", "sample_known_password.txt")
	badOutputPath := filepath.Join(outputDir, "bad", "bad.txt")

	err = os.MkdirAll(filepath.Dir(goodInputPath), 0o755)
	require.NoError(t, err)
	err = os.MkdirAll(filepath.Dir(badInputPath), 0o755)
	require.NoError(t, err)
	err = os.WriteFile(goodInputPath, goodBlob, 0o644)
	require.NoError(t, err)
	err = os.WriteFile(badInputPath, badBlob, 0o644)
	require.NoError(t, err)

	stdout, stderr, err := runGoCLI(t, rootDir, "./cmd/decode-dir", "--password", msnplus.SamplePassword, "--output-dir", outputDir, inputDir)
	require.NoError(t, err, "stderr=%s", stderr)

	got, err := os.ReadFile(goodOutputPath)
	require.NoError(t, err)
	expected, err := msnplus.SampleHTML(msnplus.SamplePassword)
	require.NoError(t, err)

	assert.Equal(t, expected, string(got))
	_, err = os.Stat(badOutputPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	assert.Contains(t, stdout, "wrote: "+goodOutputPath)
	assert.Contains(t, stdout, "password check failed: bad/bad.ple")
	assert.Contains(t, stdout, "processed=2 wrote=1 skipped=0 failed=1")
	assert.Empty(t, stderr)
}

func runGoCLI(t *testing.T, rootDir string, args ...string) (string, string, error) {
	t.Helper()

	cacheDir := filepath.Join(t.TempDir(), "gocache")
	err := os.MkdirAll(cacheDir, 0o755)
	require.NoError(t, err)

	cmdArgs := append([]string{"run"}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Dir = rootDir
	cmd.Env = append(os.Environ(), "GOCACHE="+cacheDir)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	return strings.TrimSpace(stdout.String()), strings.TrimSpace(stderr.String()), err
}

func repoRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)

	return filepath.Clean(filepath.Join(filepath.Dir(filename), ".."))
}
