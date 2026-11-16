package parsers

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/DanDreadless/atropos/internal/detect"
)

// odlEncrypt obfuscates a string as OneDrive does: UTF-16, PKCS#7, AES-CBC
// with a zero IV, URL-safe base64 without padding.
func odlEncrypt(s string, key []byte) string {
	var pt []byte
	for _, c := range utf16.Encode([]rune(s)) {
		pt = binary.LittleEndian.AppendUint16(pt, c)
	}
	pad := aes.BlockSize - len(pt)%aes.BlockSize
	pt = append(pt, bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, _ := aes.NewCipher(key)
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(ct, pt)
	return strings.NewReplacer("/", "_", "+", "-", "=", "").Replace(base64.StdEncoding.EncodeToString(ct))
}

func odlStr(s string) []byte {
	return append(binary.LittleEndian.AppendUint32(nil, uint32(len(s))), s...)
}

// odlFile builds a version 3 log: the 256-byte header, then records of a
// 32-byte header, 24 bytes of context and the data.
func odlFile(compress bool, recs ...[3]any) []byte {
	head := make([]byte, odlHeaderSize)
	copy(head, "EBFGONED")
	binary.LittleEndian.PutUint32(head[8:], 3)
	copy(head[24:], "25.001.0101.0001")
	var body bytes.Buffer
	for _, r := range recs {
		data := append(odlStr(r[0].(string)), 0, 0, 0, 0)
		data = append(data, odlStr(r[1].(string))...)
		for _, p := range r[2].([]string) {
			data = append(data, 0x99) // a non-text byte before each parameter, as real records have
			data = append(data, odlStr(p)...)
		}
		h := make([]byte, 32)
		copy(h, []byte{0xCC, 0xDD, 0xEE, 0xFF})
		binary.LittleEndian.PutUint64(h[8:], 1714564800000) // 2024-05-01T12:00:00Z
		binary.LittleEndian.PutUint32(h[24:], uint32(24+len(data)))
		body.Write(h)
		body.Write(make([]byte, 24))
		body.Write(data)
	}
	if compress {
		var z bytes.Buffer
		w := gzip.NewWriter(&z)
		w.Write(body.Bytes())
		w.Close()
		return append(head, z.Bytes()...)
	}
	return append(head, body.Bytes()...)
}

func keystore(key []byte) []byte {
	// Real keystores end the key with two NUL characters.
	return []byte(fmt.Sprintf(`[{"CreatedTime" : 1700000000, "Key" : "%s\u0000\u0000", "Version" : 1}]`, base64.StdEncoding.EncodeToString(key)))
}

func TestOneDriveLog(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	other := bytes.Repeat([]byte{9}, 32)
	secret := odlEncrypt("Budget 2024.xlsx", key)
	folder := odlEncrypt("Finance", key)
	for _, compress := range []bool{false, true} {
		log := write(t, "SyncEngine-2024-05-01.odl", odlFile(compress,
			[3]any{"SyncEngine.cpp", "UploadFile", []string{`C:\Users\x\OneDrive\` + folder + `\` + secret, "size=1234"}},
			[3]any{"cache.cpp", "Find", []string{"noise"}},
			[3]any{"Idle.cpp", "Tick", []string{}},
		))
		ks := write(t, "general.keystore", keystore(key))
		wrong := write(t, "general.keystore", keystore(other))
		if k := run(t, ks, nil); k.err != nil || k.facts["onedrive_keystore.keys"] != "1" || strings.Contains(fmt.Sprint(k.facts, k.notes), base64.StdEncoding.EncodeToString(key)) {
			t.Fatalf("keystore: %v %v %v", k.err, k.facts, k.notes)
		}
		r := run(t, log, func(c *Context) {
			if c.Kind != detect.ODL {
				t.Fatalf("kind %s", c.Kind)
			}
			c.Segments = []string{wrong, ks}
		})
		if r.err != nil || len(r.warns) > 0 || len(r.events) != 1 {
			t.Fatalf("%v %v %d", r.err, r.warns, len(r.events))
		}
		e := r.events[0]
		params := e.Fields["params"].([]string)
		if utc(e) != "2024-05-01T12:00:00Z" || params[0] != `C:\Users\x\OneDrive\Finance\Budget 2024.xlsx` || params[1] != "size=1234" ||
			e.Fields["function"] != "UploadFile" || r.facts["onedrive_log.onedrive_version"] != "25.001.0101.0001" {
			t.Errorf("compress=%v: %+v %v", compress, e, r.facts)
		}
		if !strings.Contains(strings.Join(r.notes, " "), "3 records, 1 put on the timeline (2 left out") {
			t.Errorf("notes: %v", r.notes)
		}
		// Without the keystore the strings stay as they are.
		r = run(t, log, nil)
		if p := r.events[0].Fields["params"].([]string); !strings.Contains(p[0], secret) {
			t.Errorf("without a key: %q", p[0])
		}
	}
}

func TestOneDriveLogDamaged(t *testing.T) {
	good := odlFile(false, [3]any{"a.cpp", "f", []string{"hello world"}})
	cut := good[:len(good)-5]
	bad := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(bad[odlHeaderSize+24:], 0xFFFFFF)
	for i, b := range [][]byte{cut, bad, good[:odlHeaderSize+10]} {
		r := run(t, write(t, fmt.Sprintf("x%d.odl", i), b), nil)
		if r.err != nil || len(r.warns) == 0 && i < 2 {
			t.Errorf("case %d: %v %v", i, r.err, r.warns)
		}
	}
}
