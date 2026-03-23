package msnplus

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type DecodeDirectoryStats struct {
	Processed int
	Wrote     int
	Skipped   int
	Failed    int
}

type decodeOutput interface {
	Exists(path string) (bool, error)
	WriteFile(path string, data []byte) error
	DisplayPath(path string) string
}

func DecryptDirectory(inputDir string, outputDir string, password string, logf func(string, ...any)) (DecodeDirectoryStats, error) {
	inputDir = filepath.Clean(inputDir)
	outputDir = filepath.Clean(outputDir)

	return decryptDirectoryFS(os.DirFS(inputDir), osOutputFS{root: outputDir}, password, logf)
}

func decryptDirectoryFS(input fs.FS, output decodeOutput, password string, logf func(string, ...any)) (DecodeDirectoryStats, error) {
	var stats DecodeDirectoryStats

	err := fs.WalkDir(input, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".ple") {
			return nil
		}

		stats.Processed++

		outputPath := decodedRelativePath(path)

		exists, err := output.Exists(outputPath)
		if err != nil {
			return fmt.Errorf("stat output path %s: %w", output.DisplayPath(outputPath), err)
		}
		if exists {
			stats.Skipped++
			if logf != nil {
				logf("skip existing: %s", output.DisplayPath(outputPath))
			}
			return nil
		}

		blob, err := fs.ReadFile(input, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		plaintext, err := DecryptPayload(blob, password)
		if err != nil {
			if errors.Is(err, ErrPasswordCheckFailed) {
				stats.Failed++
				if logf != nil {
					logf("password check failed: %s", path)
				}
				return nil
			}
			return fmt.Errorf("decrypt %s: %w", path, err)
		}

		if err := output.WriteFile(outputPath, plaintext); err != nil {
			return fmt.Errorf("write %s: %w", output.DisplayPath(outputPath), err)
		}

		stats.Wrote++
		if logf != nil {
			logf("wrote: %s", output.DisplayPath(outputPath))
		}

		return nil
	})
	if err != nil {
		return DecodeDirectoryStats{}, err
	}

	return stats, nil
}

type osOutputFS struct {
	root string
}

func (o osOutputFS) Exists(path string) (bool, error) {
	_, err := os.Stat(o.fullPath(path))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (o osOutputFS) WriteFile(path string, data []byte) error {
	fullPath := o.fullPath(path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(fullPath, data, 0o644)
}

func (o osOutputFS) DisplayPath(path string) string {
	return o.fullPath(path)
}

func (o osOutputFS) fullPath(path string) string {
	return filepath.Join(o.root, filepath.FromSlash(path))
}

func decodedRelativePath(relPath string) string {
	ext := filepath.Ext(relPath)
	if strings.EqualFold(ext, ".ple") {
		return strings.TrimSuffix(relPath, ext) + ".txt"
	}
	return relPath + ".txt"
}
