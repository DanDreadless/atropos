package imagetest

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// OneDriveLog returns a version 3 OneDrive log with one record whose single
// parameter is secret, encrypted with key as OneDrive does, and the
// general.keystore that holds the key.
func OneDriveLog(key []byte, secret string) (log, keystore []byte) {
	var pt []byte
	for _, c := range utf16.Encode([]rune(secret)) {
		pt = binary.LittleEndian.AppendUint16(pt, c)
	}
	pad := aes.BlockSize - len(pt)%aes.BlockSize
	pt = append(pt, bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, _ := aes.NewCipher(key)
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(ct, pt)
	word := strings.NewReplacer("/", "_", "+", "-", "=", "").Replace(base64.StdEncoding.EncodeToString(ct))
	str := func(s string) []byte { return append(binary.LittleEndian.AppendUint32(nil, uint32(len(s))), s...) }
	data := append(append(append(str("SyncEngine.cpp"), 0, 0, 0, 0), str("UploadFile")...), 0x99)
	data = append(data, str(word)...)
	head := make([]byte, 0x100)
	copy(head, "EBFGONED")
	binary.LittleEndian.PutUint32(head[8:], 3)
	h := make([]byte, 32)
	copy(h, []byte{0xCC, 0xDD, 0xEE, 0xFF})
	binary.LittleEndian.PutUint64(h[8:], 1714564800000)
	binary.LittleEndian.PutUint32(h[24:], uint32(24+len(data)))
	log = append(append(append(head, h...), make([]byte, 24)...), data...)
	keystore = []byte(fmt.Sprintf(`[{"CreatedTime" : 1700000000, "Key" : "%s\u0000\u0000", "Version" : 1}]`, base64.StdEncoding.EncodeToString(key)))
	return log, keystore
}
