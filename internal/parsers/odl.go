package parsers

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// OneDrive's logs (.odl, .odlgz, .odlsent, .aodl), in %LOCALAPPDATA%\
// Microsoft\OneDrive\logs\<folder>. Each record has a time (Unix
// milliseconds), the source file and function that wrote it, and its
// parameters, among them file names and paths. Since 2022 the sensitive
// parts are AES-encrypted with a key kept in general.keystore in the same
// folder.
//
// Written from Yogesh Khatri's odl.py (MIT licence; the record layouts,
// string extraction and decryption), and run on the owner's own logs. The
// keystore is the only other file the parser reads (Context.Segments):
// every keystore in the case is offered, and the one whose key decrypts
// the log's strings is used, so a log is paired with its key by content.
// The older ObfuscationStringMap.txt is not read.

const (
	odlMaxFile    = 256 << 20
	odlMaxRecord  = 1 << 20
	odlHeaderSize = 0x100
)

type odlParser struct{}

func (odlParser) Name() string { return "onedrive-log" }
func (odlParser) Version() string {
	return "1 (native: ODL versions 2 and 3, gzip, AES strings with the keystore that fits)"
}

type keystoreParser struct{}

func (keystoreParser) Name() string { return "onedrive-keystore" }
func (keystoreParser) Version() string {
	return "1 (native: records the key's presence, never its value)"
}

// odlKeys reads a keystore: a JSON list of {CreatedTime, Key, Version}.
func odlKeys(b []byte) ([][]byte, string) {
	b = bytes.TrimPrefix(b, []byte("\xEF\xBB\xBF"))
	if len(b) >= 2 && b[1] == 0 {
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(b[2*i:])
		}
		b = []byte(string(utf16.Decode(u)))
	}
	var list []struct {
		Key         string
		Version     int
		CreatedTime any
	}
	if json.Unmarshal(b, &list) != nil {
		return nil, ""
	}
	var keys [][]byte
	version := ""
	for _, k := range list {
		// Real keystores end the key with two NUL characters, which a
		// lenient decoder skips.
		raw, err := base64.StdEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(k.Key), "\x00"))
		if err == nil && (len(raw) == 16 || len(raw) == 24 || len(raw) == 32) {
			keys = append(keys, raw)
			version = fmt.Sprint(k.Version)
		}
	}
	return keys, version
}

func (keystoreParser) Parse(ctx *Context) error {
	b, err := io.ReadAll(io.LimitReader(ctx.File, 1<<20))
	if err != nil {
		return err
	}
	keys, version := odlKeys(b)
	if len(keys) == 0 {
		return fmt.Errorf("not a OneDrive keystore")
	}
	ctx.Fact("onedrive_keystore.keys", fmt.Sprint(len(keys)), "keys in the keystore (their values are not recorded)")
	ctx.Fact("onedrive_keystore.version", version, "keystore version")
	ctx.Note("a OneDrive log keystore: the key that decrypts the logs in the same folder. It is used, not shown, when those logs are parsed; add them to the case with it")
	return nil
}

// odlDecrypt decrypts one obfuscated word, or returns "".
func odlDecrypt(word string, key []byte) string {
	if len(word) < 22 || len(word)%4 == 1 {
		return ""
	}
	w := strings.NewReplacer("_", "/", "-", "+").Replace(word)
	if r := len(w) % 4; r != 0 {
		w += strings.Repeat("=", 4-r)
	}
	ct, err := base64.StdEncoding.DecodeString(w)
	if err != nil || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return ""
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(pt, ct)
	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(pt) {
		return ""
	}
	for _, c := range pt[len(pt)-pad:] {
		if int(c) != pad {
			return ""
		}
	}
	pt = pt[:len(pt)-pad]
	// UTF-16, or UTF-32 with some keys.
	if len(pt)%2 == 0 {
		u := make([]uint16, len(pt)/2)
		ok := true
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(pt[2*i:])
			if u[i] == 0 {
				ok = false
			}
		}
		if ok {
			return string(utf16.Decode(u))
		}
	}
	if len(pt)%4 == 0 {
		var r []rune
		for i := 0; i < len(pt); i += 4 {
			c := rune(binary.LittleEndian.Uint32(pt[i:]))
			if c == 0 || !utf8.ValidRune(c) {
				return ""
			}
			r = append(r, c)
		}
		return string(r)
	}
	return ""
}

const odlTokens = `:\.@%#&*|{}!?<>;:~()//"'`

// odlReplace decrypts the words of a string, keeping its separators.
func odlReplace(s string, key []byte, decrypted *int) string {
	if key == nil {
		return s
	}
	var out, word strings.Builder
	flush := func() {
		if word.Len() == 0 {
			return
		}
		if d := odlDecrypt(word.String(), key); d != "" {
			*decrypted++
			out.WriteString(d)
		} else {
			out.WriteString(word.String())
		}
		word.Reset()
	}
	for _, c := range s {
		if strings.ContainsRune(odlTokens, c) {
			flush()
			out.WriteRune(c)
		} else {
			word.WriteRune(c)
		}
	}
	flush()
	return out.String()
}

// odlStrings finds the parameters that are strings: a run of printable
// ASCII after its own 32-bit length, as odl.py finds them.
func odlStrings(b []byte) []string {
	var out []string
	for i := 4; i < len(b); {
		if b[i] < 0x20 || b[i] > 0x7E {
			if !(b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
				i++
				continue
			}
		}
		j := i
		for j < len(b) && (b[j] >= 0x20 && b[j] <= 0x7E || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
			j++
		}
		if j-i >= 4 {
			n := int(binary.LittleEndian.Uint32(b[i-4:]))
			if j-i-n <= 5 && n > 0 {
				if n > j-i {
					n = j - i
				}
				out = append(out, strings.TrimRight(string(b[i:i+n]), "\r\n"))
			}
		}
		i = j + 1
	}
	return out
}

func odlString(b []byte) (string, int) {
	if len(b) < 4 {
		return "", len(b)
	}
	n := int(binary.LittleEndian.Uint32(b))
	if n <= 0 || 4+n > len(b) {
		return "", 4
	}
	return strings.ToValidUTF8(string(b[4:4+n]), "?"), 4 + n
}

type odlRecord struct {
	ms             int64
	file, function string
	params         []string
	offset         int64
}

// odlRecords reads the records after the file header.
func odlRecords(b []byte, version uint32) ([]odlRecord, string) {
	var out []odlRecord
	le := binary.LittleEndian
	for pos := 0; ; {
		var hdr, dataLen, ctxLen int
		switch version {
		case 2:
			hdr = 56
		default:
			hdr = 32
		}
		if pos+hdr > len(b) {
			return out, ""
		}
		h := b[pos : pos+hdr]
		if !bytes.Equal(h[:4], []byte{0xCC, 0xDD, 0xEE, 0xFF}) {
			return out, fmt.Sprintf("a record at offset %d has no signature; reading stopped there", pos)
		}
		ms := int64(le.Uint64(h[8:]))
		if version == 2 {
			dataLen = int(le.Uint32(h[48:]))
		} else {
			ctxLen = int(le.Uint16(h[4:]))
			dataLen = int(le.Uint32(h[24:]))
		}
		if dataLen <= 4 {
			return out, ""
		}
		body := pos + hdr
		if version != 2 {
			skip := ctxLen
			if skip == 0 {
				skip = 24
			}
			body += skip
			dataLen -= skip
		}
		if dataLen <= 0 || dataLen > odlMaxRecord || body+dataLen > len(b) {
			return out, fmt.Sprintf("the record at offset %d is cut short or has an impossible length", pos)
		}
		d := b[body : body+dataLen]
		file, k := odlString(d)
		k += 4 // flags
		var function string
		if k < len(d) {
			var k2 int
			function, k2 = odlString(d[k:])
			k += k2
		}
		r := odlRecord{ms: ms, file: file, function: function, offset: int64(pos)}
		if k < len(d) {
			r.params = odlStrings(d[k:])
		}
		out = append(out, r)
		pos = body + dataLen
	}
}

// odlNoise is what odl.py leaves out by default: records with nothing in
// them, and the chattiest ones that say nothing about what was done.
func odlNoise(r odlRecord) bool {
	switch {
	case len(r.params) == 0:
		return true
	case r.function == "Find" && r.file == "cache.cpp",
		r.function == "RecordCallTimeTaken" && r.file == "AclHelper.cpp",
		r.function == "UpdateSyncStatusText" && r.file == "ActivityCenterHeaderModel.cpp",
		r.function == "FireEvent" && r.file == "EventMachine.cpp":
		return true
	}
	switch r.file {
	case "LogUploader2.cpp", "LogUploader.cpp", "ServerRefreshState.cpp", "SyncTelemetry.cpp":
		return true
	}
	return false
}

func (odlParser) Parse(ctx *Context) error {
	if ctx.Size > odlMaxFile {
		return fmt.Errorf("log of %d bytes is larger than any real one", ctx.Size)
	}
	b := make([]byte, ctx.Size)
	if _, err := io.ReadFull(io.NewSectionReader(ctx.File, 0, ctx.Size), b); err != nil {
		return err
	}
	if len(b) < odlHeaderSize || string(b[:8]) != "EBFGONED" {
		return fmt.Errorf("not a OneDrive log")
	}
	version := binary.LittleEndian.Uint32(b[8:])
	if version != 2 && version != 3 {
		return fmt.Errorf("OneDrive log version %d is not one this version reads", version)
	}
	ctx.Fact("onedrive_log.version", fmt.Sprint(version), "ODL format version")
	if v := strings.TrimRight(string(b[24:24+0x40]), "\x00"); v != "" {
		ctx.Fact("onedrive_log.onedrive_version", clean(trunc(v, 64)), "the OneDrive version that wrote the log")
	}
	if v := strings.TrimRight(string(b[24+0x40:24+0x80]), "\x00"); v != "" {
		ctx.Fact("onedrive_log.windows_version", clean(trunc(v, 64)), "the Windows version it ran on")
	}
	data := b[odlHeaderSize:]
	if bytes.HasPrefix(data, []byte{0x1F, 0x8B}) {
		z, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("compressed log: %v", err)
		}
		unpacked, err := io.ReadAll(io.LimitReader(z, 2*odlMaxFile))
		if err != nil && len(unpacked) == 0 {
			return fmt.Errorf("compressed log: %v", err)
		}
		if err != nil {
			ctx.Warn("the compressed log is damaged after %d bytes: %v", len(unpacked), err)
		}
		data = unpacked
	}
	recs, why := odlRecords(data, version)
	if why != "" {
		ctx.Warn("%s", why)
	}

	// The key: whichever keystore offered decrypts most of this log.
	var key []byte
	keyFrom := ""
	best := 0
	for _, p := range ctx.Segments {
		kb, err := os.ReadFile(p)
		if err != nil || len(kb) > 1<<20 {
			continue
		}
		keys, _ := odlKeys(kb)
		for _, k := range keys {
			n := 0
			for i, r := range recs {
				if i > 2000 {
					break
				}
				for _, s := range r.params {
					odlReplace(s, k, &n)
				}
			}
			if n > best {
				best, key, keyFrom = n, k, filepath.Base(p)
			}
		}
	}
	decrypted, emitted, skipped := 0, 0, 0
	for i, r := range recs {
		if odlNoise(r) {
			skipped++
			continue
		}
		params := make([]string, len(r.params))
		for j, s := range r.params {
			params[j] = clean(trunc(odlReplace(s, key, &decrypted), 2000))
		}
		stamp, ok := unixMillis(r.ms)
		if !ok {
			continue
		}
		emitted++
		if err := ctx.Emit(Event{Stamp: stamp, Type: "onedrive-log", Category: CatLog, Source: "onedrive", Host: ctx.Host,
			Message: clean(trunc(fmt.Sprintf("OneDrive %s %s: %s", r.file, r.function, strings.Join(params, " | ")), 3000)),
			Fields:  map[string]any{"code_file": clean(trunc(r.file, 200)), "function": clean(trunc(r.function, 200)), "params": params, "record": i + 1},
			Ref:     fmt.Sprintf("record %d at offset %d", i+1, r.offset)}); err != nil {
			return err
		}
	}
	switch {
	case key != nil:
		ctx.Fact("onedrive_log.keystore", keyFrom, "SHA-256 of the keystore whose key decrypted this log's strings")
		ctx.Note("%d records, %d put on the timeline (%d left out as odl.py leaves them out: empty, or the client's own housekeeping); %d encrypted strings decrypted with the key from keystore %s", len(recs), emitted, skipped, decrypted, keyFrom)
	case len(ctx.Segments) > 0:
		ctx.Note("%d records, %d put on the timeline (%d left out). None of the keystores in the case decrypts this log, so its encrypted strings are shown as they are; add the general.keystore from the log's own folder", len(recs), emitted, skipped)
	default:
		ctx.Note("%d records, %d put on the timeline (%d left out). Its encrypted strings are shown as they are: add the general.keystore from the log's own folder to the case to decrypt them", len(recs), emitted, skipped)
	}
	return nil
}
