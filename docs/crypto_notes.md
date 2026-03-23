## Messenger Plus Log Viewer Crypto Notes

Target: `Log Viewer.exe`

- PE32 native x86 Windows binary
- Timestamp: 2014-08-06 04:35:22 UTC
- PDB path: `C:\Kiimhari\Messenger Plus! For Skype-No-Licensing\Messenger Plus! For Skype\Output\Release\Log Viewer.pdb`

### Key findings

The log password logic is not using WinZip AES or the bundled OpenSSL code paths. The log-viewer-specific path is a small CryptoAPI wrapper around:

- `CryptAcquireContextW`
- `CryptCreateHash`
- `CryptHashData`
- `CryptDeriveKey`
- `CryptDecrypt`

The relevant functions are:

- `0x004A4B70`: acquire provider, hash transformed password, derive decryption key
- `0x004A4D90`: transform the password before hashing
- `0x004A4768`: read encrypted header and verify the password
- `0x004A4980`: read and decrypt payload chunks

### Provider and algorithm

`0x004A4B70` acquires:

- Provider: `Microsoft Enhanced Cryptographic Provider v1.0`
- Container: `MessengerPlusEncryptProvider`

It creates:

- Hash algorithm: `CALG_MD5` (`0x8003`)
- Cipher algorithm: `CALG_RC4` (`0x6801`)
- Key flags: `0x00800000` (128-bit key length)

So the effective crypto is:

- transform password
- MD5 over transformed password bytes
- derive a 128-bit RC4 key from that MD5 hash

### Password transform

`0x004A4D90` does not hash the raw password. It first builds a new string where each element is the sum of the current element and the next one, wrapping on the final element.

Byte mode:

```text
out[i] = (in[i] + in[(i + 1) % n]) & 0xff
if out[i] == 0:
    out[i] = 0x73   // 's'
```

Wide mode:

```text
out[i] = (in[i] + in[(i + 1) % n]) & 0xffff
if out[i] == 0:
    out[i] = 0x0073
```

The binary supports both ANSI and UTF-16LE password material. A file header flag controls which path is used.

### Password-check header

In the `.ple` sample now in this directory, the encrypted section is wrapped by a small file header:

1. `u16 file_version` = `0x0110`
2. `"MPLE1<<\0"`

Immediately after that wrapper, the password validation path at `0x004A4768` reads:

1. `u32 encoding_flag`
2. `u32 encrypted_check_len`
3. `encrypted_check_len` bytes of encrypted data

It then derives the key from the supplied password and decrypts the blob. The expected plaintext is:

```text
PasswordCheck
```

Notes:

- `encrypted_check_len` is rejected if it is `0` or greater than `0x100`
- the literal `PasswordCheck` is stored at `0x006A4348`

### Payload framing

After the password-check blob, the viewer decrypts the remaining payload as a series of chunks.

The chunk parser at `0x004A4980` expects repeated:

1. `u32 magic` = `0x00A3FFE9`
2. `u32 chunk_len`
3. `chunk_len` bytes of ciphertext

Each chunk is passed to `CryptDecrypt` with:

- `hHash = 0`
- `Final = TRUE`
- `dwFlags = 0`

and the decrypted bytes are written directly to the output stream.

### Important inference

The same `HCRYPTKEY` is reused for:

- the `PasswordCheck` blob
- each payload chunk

Because each `CryptDecrypt` call uses `Final=TRUE`, the implementation appears to rely on each blob/chunk being decryptable as an independent RC4 operation with the same derived key. The included Python helper follows that model by default.

This is an inference from the control flow. I have not validated it against a real encrypted log sample in this workspace.

### Practical build notes

To build a compatible viewer, you need:

- the password transform above
- MD5 over transformed bytes
- RC4-128 from the derived key
- header parsing for `encoding_flag` and `encrypted_check_len`
- chunk parsing for `0x00A3FFE9` records

The companion file `mp_log_crypto.py` implements this recovered logic as a standalone parser/decryptor.
