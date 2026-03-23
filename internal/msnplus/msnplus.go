package msnplus

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"text/template"
	"unicode/utf16"
)

var (
	ErrPasswordCheckFailed = errors.New("password check failed")
	ErrPasswordNotFound    = errors.New("password not found in candidate file")
	passwordCheck          = []byte("PasswordCheck")
	fileMagic              = []byte("MPLE1<<\x00")
)

const chunkMagic uint32 = 0x00A3FFE9

const (
	SamplePassword    = "viewer-test-password"
	SamplePLEFilename = "sample_known_password.ple"
)

//go:embed templates/sample.html.tmpl
var templateFS embed.FS

var sampleHTMLTemplate = template.Must(template.ParseFS(templateFS, "templates/sample.html.tmpl"))

type Header struct {
	FileVersion       uint16
	EncodingFlag      uint32
	EncryptedCheckLen uint32
	EncryptedCheck    []byte
	PayloadOffset     int
}

func FindPasswordInFile(blob []byte, path string, onAttempt func(int)) (string, Header, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", Header{}, 0, err
	}
	defer f.Close()

	return FindPasswordInReader(blob, f, onAttempt)
}

func FindPasswordInReader(blob []byte, r io.Reader, onAttempt func(int)) (string, Header, int, error) {
	var (
		foundPassword string
		header        Header
		tried         int
	)

	err := streamLines(r, func(line []byte) bool {
		tried++
		if onAttempt != nil {
			onAttempt(tried)
		}

		candidate := string(line)
		verifiedHeader, err := VerifyPassword(blob, candidate)
		if err != nil {
			return false
		}

		foundPassword = candidate
		header = verifiedHeader
		return true
	})
	if err != nil {
		return "", Header{}, tried, err
	}
	if foundPassword == "" {
		return "", Header{}, tried, ErrPasswordNotFound
	}

	return foundPassword, header, tried, nil
}

func ParseHeader(blob []byte) (Header, error) {
	base := 0
	var fileVersion uint16

	if len(blob) >= 10 && bytes.Equal(blob[2:10], fileMagic) {
		fileVersion = binary.LittleEndian.Uint16(blob[:2])
		base = 10
	}

	if len(blob) < base+8 {
		return Header{}, errors.New("file is too small to contain the encrypted header")
	}

	encodingFlag := binary.LittleEndian.Uint32(blob[base : base+4])
	encryptedCheckLen := binary.LittleEndian.Uint32(blob[base+4 : base+8])
	if encryptedCheckLen == 0 || encryptedCheckLen > 0x100 {
		return Header{}, fmt.Errorf("invalid encrypted_check_len: %d", encryptedCheckLen)
	}

	start := base + 8
	end := start + int(encryptedCheckLen)
	if end > len(blob) {
		return Header{}, errors.New("file ends before the password-check blob")
	}

	return Header{
		FileVersion:       fileVersion,
		EncodingFlag:      encodingFlag,
		EncryptedCheckLen: encryptedCheckLen,
		EncryptedCheck:    blob[start:end],
		PayloadOffset:     end,
	}, nil
}

func VerifyPassword(blob []byte, password string) (Header, error) {
	header, err := ParseHeader(blob)
	if err != nil {
		return Header{}, err
	}

	key, err := deriveRC4Key(password, header.EncodingFlag != 0)
	if err != nil {
		return Header{}, err
	}

	decrypted, err := rc4Crypt(key, header.EncryptedCheck)
	if err != nil {
		return Header{}, err
	}
	if !bytes.Equal(decrypted, passwordCheck) {
		return Header{}, ErrPasswordCheckFailed
	}

	return header, nil
}

func DecryptPayload(blob []byte, password string) ([]byte, error) {
	header, err := VerifyPassword(blob, password)
	if err != nil {
		return nil, err
	}

	key, err := deriveRC4Key(password, header.EncodingFlag != 0)
	if err != nil {
		return nil, err
	}

	offset := header.PayloadOffset

	var out bytes.Buffer
	for offset < len(blob) {
		chunk, nextOffset, err := parseChunk(blob, offset)
		if err != nil {
			return nil, err
		}
		plaintext, err := rc4Crypt(key, chunk)
		if err != nil {
			return nil, err
		}
		out.Write(plaintext)
		offset = nextOffset
	}

	return out.Bytes(), nil
}

func GenerateSampleFile(path string, password string) error {
	blob, err := GenerateSampleBlob(password)
	if err != nil {
		return err
	}

	return os.WriteFile(path, blob, 0o644)
}

func GenerateSampleBlob(password string) ([]byte, error) {
	key, err := deriveRC4Key(password, true)
	if err != nil {
		return nil, err
	}

	encryptedCheck, err := rc4Crypt(key, passwordCheck)
	if err != nil {
		return nil, err
	}

	payload, err := SampleHTML(password)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := rc4Crypt(key, []byte(payload))
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	if err := binary.Write(&out, binary.LittleEndian, uint16(0x0110)); err != nil {
		return nil, err
	}
	out.Write(fileMagic)
	if err := binary.Write(&out, binary.LittleEndian, uint32(1)); err != nil {
		return nil, err
	}
	if err := binary.Write(&out, binary.LittleEndian, uint32(len(encryptedCheck))); err != nil {
		return nil, err
	}
	out.Write(encryptedCheck)
	if err := binary.Write(&out, binary.LittleEndian, chunkMagic); err != nil {
		return nil, err
	}
	if err := binary.Write(&out, binary.LittleEndian, uint32(len(encryptedPayload))); err != nil {
		return nil, err
	}
	out.Write(encryptedPayload)

	return out.Bytes(), nil
}

func SampleHTML(password string) (string, error) {
	var out bytes.Buffer
	if err := sampleHTMLTemplate.Execute(&out, struct {
		Password string
	}{
		Password: password,
	}); err != nil {
		return "", err
	}

	return out.String(), nil
}

func streamLines(r io.Reader, handleLine func([]byte) bool) error {
	buf := make([]byte, 1024*1024)
	var pending []byte

	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := append(pending, buf[:n]...)

			start := 0
			for {
				i := bytes.IndexByte(chunk[start:], '\n')
				if i == -1 {
					break
				}

				end := start + i
				line := bytes.TrimSuffix(chunk[start:end], []byte{'\r'})
				if done := handleLine(line); done {
					return nil
				}

				start = end + 1
			}

			pending = append(pending[:0], chunk[start:]...)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	if len(pending) > 0 {
		pending = bytes.TrimSuffix(pending, []byte{'\r'})
		if done := handleLine(pending); done {
			return nil
		}
	}

	return nil
}

func parseChunk(blob []byte, offset int) ([]byte, int, error) {
	if offset+8 > len(blob) {
		return nil, 0, errors.New("truncated payload chunk header")
	}

	magic := binary.LittleEndian.Uint32(blob[offset : offset+4])
	chunkLen := binary.LittleEndian.Uint32(blob[offset+4 : offset+8])
	if magic != chunkMagic {
		return nil, 0, fmt.Errorf("unexpected chunk magic 0x%08x at offset 0x%x", magic, offset)
	}

	start := offset + 8
	end := start + int(chunkLen)
	if end > len(blob) {
		return nil, 0, errors.New("truncated payload chunk data")
	}

	return blob[start:end], end, nil
}

func deriveRC4Key(password string, unicodeMode bool) ([]byte, error) {
	var material []byte
	var err error

	if unicodeMode {
		material = transformPasswordUTF16LE(password)
	} else {
		material, err = transformPasswordBytes(password)
		if err != nil {
			return nil, err
		}
	}

	sum := md5.Sum(material)
	return sum[:], nil
}

func transformPasswordBytes(password string) ([]byte, error) {
	encoded, err := encodeWindows1252(password)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 {
		return []byte{}, nil
	}

	out := make([]byte, len(encoded))
	for i, cur := range encoded {
		next := encoded[(i+1)%len(encoded)]
		value := byte((uint16(cur) + uint16(next)) & 0xff)
		if value == 0 {
			value = 0x73
		}
		out[i] = value
	}
	return out, nil
}

func transformPasswordUTF16LE(password string) []byte {
	runes := []rune(password)
	codeUnits := utf16.Encode(runes)
	if len(codeUnits) == 0 {
		return []byte{}
	}

	out := make([]byte, len(codeUnits)*2)
	for i, cur := range codeUnits {
		next := codeUnits[(i+1)%len(codeUnits)]
		value := uint16(uint32(cur)+uint32(next)) & 0xffff
		if value == 0 {
			value = 0x0073
		}
		binary.LittleEndian.PutUint16(out[i*2:], value)
	}
	return out
}

func rc4Crypt(key []byte, data []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(data))
	cipher.XORKeyStream(out, data)
	return out, nil
}

func encodeWindows1252(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r <= 0x7f:
			out = append(out, byte(r))
		case r >= 0x00a0 && r <= 0x00ff:
			out = append(out, byte(r))
		default:
			b, ok := cp1252SpecialRune(r)
			if !ok {
				return nil, fmt.Errorf("password contains rune not representable in cp1252: %U", r)
			}
			out = append(out, b)
		}
	}
	return out, nil
}

func cp1252SpecialRune(r rune) (byte, bool) {
	switch r {
	case 0x20ac:
		return 0x80, true
	case 0x201a:
		return 0x82, true
	case 0x0192:
		return 0x83, true
	case 0x201e:
		return 0x84, true
	case 0x2026:
		return 0x85, true
	case 0x2020:
		return 0x86, true
	case 0x2021:
		return 0x87, true
	case 0x02c6:
		return 0x88, true
	case 0x2030:
		return 0x89, true
	case 0x0160:
		return 0x8a, true
	case 0x2039:
		return 0x8b, true
	case 0x0152:
		return 0x8c, true
	case 0x017d:
		return 0x8e, true
	case 0x2018:
		return 0x91, true
	case 0x2019:
		return 0x92, true
	case 0x201c:
		return 0x93, true
	case 0x201d:
		return 0x94, true
	case 0x2022:
		return 0x95, true
	case 0x2013:
		return 0x96, true
	case 0x2014:
		return 0x97, true
	case 0x02dc:
		return 0x98, true
	case 0x2122:
		return 0x99, true
	case 0x0161:
		return 0x9a, true
	case 0x203a:
		return 0x9b, true
	case 0x0153:
		return 0x9c, true
	case 0x017e:
		return 0x9e, true
	case 0x0178:
		return 0x9f, true
	default:
		return 0, false
	}
}
