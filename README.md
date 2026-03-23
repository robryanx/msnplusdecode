# Msn Plus Docode

Small Go utilities for working with Messenger Plus `.ple` chat logs.

## Commands

### `decode-dir`

Decrypts every `.ple` file under an input directory using a known password and writes decoded files into an output directory, preserving relative paths.

```bash
go run ./cmd/decode-dir --password viewer-test-password --output-dir ./decoded ./logs
```

Behavior:

- only files ending in `.ple` are processed
- output files are written under `--output-dir` using the same relative path
- `.ple` extensions are changed to `.txt`
- if an output file already exists, it is skipped and left unchanged

Example:

- input: `./logs/April 2005/chat.ple`
- output: `./decoded/April 2005/chat.txt`

The command prints one line per write or skip, followed by a summary:

```text
wrote: ./decoded/April 2005/chat.txt
skip existing: ./decoded/April 2005/other-chat.txt
processed=2 wrote=1 skipped=1
```
### `find-password`

Recover forgotten passwords by checking a candidates list.
Finds the password for a single `.ple` file using a candidate password list, prints the matching password and parsed header details, then exits.

```bash
go run ./cmd/find-password --password-file ./testdata/test_passwords.txt ./testdata/sample_known_password.ple
```

Arguments:

- `--password-file`: text file containing one candidate password per line
- positional argument: path to the `.ple` file

Example output:

```text
found: viewer-test-password
file_version=0x0110
encoding_flag=1
encrypted_check_len=13
payload_offset=0x1f
```

## Tests

Run all unit and integration tests with:

```bash
go test ./...
```
