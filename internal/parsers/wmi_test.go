package parsers

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

// wmiInstance builds an instance record in the layout found in a real
// repository: the class-name hash as UTF-16 hexadecimal, two FILETIMEs, the
// data length, a header that holds bytes which could pass for text, then
// the strings, each with a flag byte and a terminator.
func wmiInstance(class string, written string, values ...string) []byte {
	var data bytes.Buffer
	data.Write([]byte{0, 0, 0, 0, 0, 0xB0, 0x0A, 0x66, 0, 0, 0, 0x1B, 0, 0, 0, 0, 0, 0, 0, 0, 0x52, 0, 0, 0, 0x04, 0, 0, 0, 0x01, 0x91, 0, 0, 0x80})
	data.WriteByte(0)
	data.WriteString(class)
	data.WriteByte(0)
	for _, v := range values {
		ascii := true
		for _, r := range v {
			if r > 0x7E {
				ascii = false
			}
		}
		if ascii {
			data.WriteByte(0)
			data.WriteString(v)
			data.WriteByte(0)
			continue
		}
		data.WriteByte(1)
		for _, u := range utf16.Encode([]rune(v)) {
			binary.Write(&data, binary.LittleEndian, u)
		}
		data.Write([]byte{0, 0})
	}
	var out bytes.Buffer
	sum := sha256.Sum256([]byte(strings.ToUpper(class)))
	for _, c := range fmt.Sprintf("%X", sum[:]) {
		out.Write([]byte{byte(c), 0})
	}
	binary.Write(&out, binary.LittleEndian, filetime(written))
	binary.Write(&out, binary.LittleEndian, filetime("2019-12-07T09:00:00Z"))
	binary.Write(&out, binary.LittleEndian, uint32(data.Len()))
	out.Write(data.Bytes())
	return out.Bytes()
}

func wmiRepo(records ...[]byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x47, 0xFC, 0x9E, 0xD9, 0x70, 0x01, 0, 0})
	// What every repository holds: namespaces and other system instances.
	for i := 0; i < 12; i++ {
		b.Write(wmiInstance("__NAMESPACE", "2019-12-07T09:10:00Z", fmt.Sprintf("ns%d", i)))
		b.Write([]byte{0xEE, 0xEE, 0xEE})
	}
	for _, r := range records {
		b.Write([]byte{'A', 0}) // a byte pair before the hash that looks like one more hexadecimal character
		b.Write(r)
		b.Write(bytes.Repeat([]byte{0xEE}, 37))
	}
	for b.Len()%8192 != 0 {
		b.WriteByte(0)
	}
	return b.Bytes()
}

func TestWMISubscriptionsCarved(t *testing.T) {
	cmd := wmiInstance("CommandLineEventConsumer", "2024-05-05T03:00:00.1234567Z", "Updater", `powershell.exe -nop -w hidden -enc SQBFAFgA`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`)
	repo := wmiRepo(
		wmiInstance("__EventFilter", "2024-05-05T03:00:00Z", `root\cimv2`, "Updater", "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'", "WQL"),
		cmd,
		wmiInstance("__FilterToConsumerBinding", "2024-05-05T03:00:01Z", `CommandLineEventConsumer.Name="Updater"`, `__EventFilter.Name="Updater"`),
		cmd, // the same record in a page no longer in use
		wmiInstance("ActiveScriptEventConsumer", "2024-06-01T00:00:00Z", "Скрипт", "VBScript", `CreateObject("WScript.Shell").Run "calc"`),
		wmiInstance("Win32_Something", "2024-06-01T00:00:00Z", "not a subscription"),
	)
	r := run(t, write(t, "renamed.bin", repo), nil)
	if r.err != nil || len(r.warns) != 0 {
		t.Fatalf("err=%v warns=%v", r.err, r.warns)
	}
	if len(r.events) != 4 {
		t.Fatalf("%d events: %s", len(r.events), types(r))
	}
	f, c, b, s := r.events[0], r.events[1], r.events[2], r.events[3]
	if f.Fields["name"] != "Updater" || !strings.HasPrefix(f.Fields["query"].(string), "SELECT * FROM __InstanceModificationEvent") || f.Category != CatPersistence || f.Source != "wmi" {
		t.Errorf("filter: %+v", f)
	}
	if utc(c) != "2024-05-05T03:00:00.1234567Z" || c.Fields["class"] != "CommandLineEventConsumer" || c.Fields["name"] != "Updater" || c.Fields["copies_found"] != 2 ||
		!strings.Contains(c.Message, "-enc SQBFAFgA") || !strings.Contains(c.Type, "inferred") || c.Fields["class_defined"] != "2019-12-07T09:00:00.0000000Z" {
		t.Errorf("consumer: %s %+v", utc(c), c)
	}
	if b.Fields["filter"] != "Updater" || b.Fields["consumer_class"] != "CommandLineEventConsumer" || b.Fields["consumer"] != "Updater" ||
		b.Message != `WMI subscription: filter "Updater" runs CommandLineEventConsumer "Updater"` {
		t.Errorf("binding: %+v", b)
	}
	if v := s.Fields["values"].([]string); len(v) != 3 || v[0] != "Скрипт" || !strings.Contains(v[2], "WScript.Shell") {
		t.Errorf("script consumer values: %q", v)
	}
	if !strings.Contains(r.text, "powershell.exe -nop") || r.facts["wmi.subscription_records"] != "1 binding records, 2 consumer records, 1 filter records" {
		t.Errorf("text %q facts %v", r.text, r.facts)
	}

	// A repository with nothing but what Windows needs says so, and is still recognised.
	r = run(t, write(t, "x", wmiRepo()), nil)
	if r.err != nil || len(r.events) != 0 || r.facts["wmi.instance_records"] != "12" {
		t.Errorf("empty repository: err=%v events=%d facts=%v", r.err, len(r.events), r.facts)
	}

	// Damage must not panic or hang.
	for i := 0; i < len(repo); i += 13 {
		bad := append([]byte(nil), repo...)
		bad[i] ^= 0xFF
		run(t, write(t, "x", bad), nil)
	}
	for _, n := range []int{8192, 16384} {
		if n < len(repo) {
			run(t, write(t, "x", repo[:n]), nil)
		}
	}
}
