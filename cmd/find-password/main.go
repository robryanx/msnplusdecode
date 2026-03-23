package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/robryanx/msnplusdecode/internal/msnplus"
)

func main() {
	var passwordFile string
	var generateSample bool

	flag.StringVar(&passwordFile, "password-file", "", "file containing candidate passwords")
	flag.BoolVar(&generateSample, "generate-sample", false, "write the synthetic sample .ple fixture into testdata")
	flag.Parse()

	if generateSample {
		sampleOutput := filepath.Join("testdata", msnplus.SamplePLEFilename)
		if err := msnplus.GenerateSampleFile(sampleOutput, msnplus.SamplePassword); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("wrote sample file %s with password %q\n", sampleOutput, msnplus.SamplePassword)
		return
	}

	if passwordFile == "" {
		fmt.Fprintln(os.Stderr, "error: --password-file is required")
		os.Exit(1)
	}
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "error: input file is required")
		os.Exit(1)
	}

	blob, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	password, header, _, err := msnplus.FindPasswordInFile(blob, passwordFile, func(tried int) {
		if tried%1000000 == 0 {
			fmt.Printf("tried %d\n", tried)
		}
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("found: " + password)
	fmt.Printf("file_version=0x%04x\n", header.FileVersion)
	fmt.Printf("encoding_flag=%d\n", header.EncodingFlag)
	fmt.Printf("encrypted_check_len=%d\n", header.EncryptedCheckLen)
	fmt.Printf("payload_offset=0x%x\n", header.PayloadOffset)
}
