package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/robryanx/msnplusdecode/internal/msnplus"
)

func main() {
	var password string
	var outputDir string

	flag.StringVar(&password, "password", "", "password used to decrypt .ple files")
	flag.StringVar(&outputDir, "output-dir", "", "directory where decoded files will be written")
	flag.Parse()

	if password == "" {
		fmt.Fprintln(os.Stderr, "error: --password is required")
		os.Exit(1)
	}
	if outputDir == "" {
		fmt.Fprintln(os.Stderr, "error: --output-dir is required")
		os.Exit(1)
	}
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "error: input directory is required")
		os.Exit(1)
	}

	stats, err := msnplus.DecryptDirectory(flag.Arg(0), outputDir, password, func(format string, args ...any) {
		fmt.Printf(format+"\n", args...)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("processed=%d wrote=%d skipped=%d failed=%d\n", stats.Processed, stats.Wrote, stats.Skipped, stats.Failed)
}
