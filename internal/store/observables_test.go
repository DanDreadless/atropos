package store

import (
	"reflect"
	"testing"
)

// Each Remote Desktop record gives the computer at the other end, the
// account, and which way the connection went; console sessions, other
// logon types and other credentials give nothing.
func TestObserveRemoteDesktop(t *testing.T) {
	sec := func(eid, data string) string {
		return `{"channel":"Security","event_id":"` + eid + `","event":{"EventData":{` + data + `}}}`
	}
	ud := func(ch, eid, data string) string {
		return `{"channel":"` + ch + `","event_id":"` + eid + `","event":{"UserData":{"EventXML":{` + data + `}}}}`
	}
	cases := []struct {
		name, fields, act string
		items             []Observable
	}{
		{"4624 type 10", sec("4624", `"LogonType":10,"IpAddress":"::ffff:10.1.1.20","WorkstationName":"ws-alice","TargetUserName":"alice","TargetDomainName":"CORP"`), "rdp-in",
			[]Observable{{"ip", "10.1.1.20", "source"}, {"host", "WS-ALICE", "source"}, {"account", `CORP\alice`, "target"}}},
		{"4624 type 12 as text", sec("4624", `"LogonType":"12","IpAddress":"-","WorkstationName":"-","TargetUserName":"bob"`), "rdp-in",
			[]Observable{{"account", "bob", "target"}}},
		{"4624 type 3", sec("4624", `"LogonType":3,"IpAddress":"10.1.1.20"`), "", nil},
		{"4778", sec("4778", `"ClientAddress":"10.1.1.20","ClientName":"WS-ALICE","AccountName":"alice","AccountDomain":"CORP"`), "rdp-in",
			[]Observable{{"ip", "10.1.1.20", "source"}, {"host", "WS-ALICE", "source"}, {"account", `CORP\alice`, "target"}}},
		{"4648 to TERMSRV", sec("4648", `"TargetServerName":"srv-file01.corp.example","TargetInfo":"TERMSRV/srv-file01.corp.example","TargetUserName":"alice","TargetDomainName":"CORP","SubjectUserName":"alice","SubjectDomainName":"CORP"`), "rdp-out",
			[]Observable{{"host", "SRV-FILE01.CORP.EXAMPLE", "target"}, {"account", `CORP\alice`, "target"}, {"account", `CORP\alice`, "subject"}}},
		{"4648 to localhost", sec("4648", `"TargetServerName":"localhost","TargetInfo":"TERMSRV/10.1.1.50","TargetUserName":"alice"`), "rdp-out",
			[]Observable{{"ip", "10.1.1.50", "target"}, {"account", "alice", "target"}}},
		{"4648 to a share", sec("4648", `"TargetServerName":"srv","TargetInfo":"cifs/srv"`), "", nil},
		{"1149", ud(chRCM, "1149", `"Param1":"alice","Param2":"CORP","Param3":"10.1.1.20"`), "rdp-in",
			[]Observable{{"ip", "10.1.1.20", "source"}, {"account", `CORP\alice`, "target"}}},
		{"21 remote", ud(chLSM, "21", `"User":"CORP\\alice","SessionID":"2","Address":"10.1.1.20"`), "rdp-in",
			[]Observable{{"ip", "10.1.1.20", "source"}, {"account", `CORP\alice`, "target"}}},
		{"21 at the console", ud(chLSM, "21", `"User":"CORP\\alice","Address":"LOCAL"`), "", nil},
		{"131 IPv4", `{"channel":"` + chCoreTS + `","event_id":"131","event":{"EventData":{"ClientIP":"10.1.1.20:50642"}}}`, "rdp-in",
			[]Observable{{"ip", "10.1.1.20", "source"}}},
		{"131 IPv6", `{"channel":"` + chCoreTS + `","event_id":"131","event":{"EventData":{"ClientIP":"[fe80::1]:50642"}}}`, "rdp-in",
			[]Observable{{"ip", "fe80::1", "source"}}},
		{"1024 by name", `{"channel":"` + chRDPCli + `","event_id":"1024","event":{"EventData":{"Value":"srv-file01"}}}`, "rdp-out",
			[]Observable{{"host", "SRV-FILE01", "target"}}},
		{"1102 by address", `{"channel":"` + chRDPCli + `","event_id":"1102","event":{"EventData":{"Value":"10.1.1.50"}}}`, "rdp-out",
			[]Observable{{"ip", "10.1.1.50", "target"}}},
		{"not JSON", `{`, "", nil},
	}
	for _, c := range cases {
		var oe ObservedEvent
		ok := observeEvent(&oe, c.fields)
		if ok != (c.act != "") || oe.Act != c.act && ok || !reflect.DeepEqual(oe.Items, c.items) && ok {
			t.Errorf("%s: %v %q %+v, want %q %+v", c.name, ok, oe.Act, oe.Items, c.act, c.items)
		}
	}
}

// A host's stated clock difference is read whichever way it is written,
// and refused when which way it was out cannot be told.
func TestParseClockOffset(t *testing.T) {
	for in, want := range map[string]int64{
		"3 minutes ahead": 180, "90 seconds behind": -90, "1 min 30 s slow": -90, "+3m": 180, "-1m30s": -90,
		"-00:01:30": -90, "1h2m fast": 3720, "0": 0, "none": 0, "Correct": 0, "2 minutes and 5 seconds fast": 125, "+00:00:07": 7,
	} {
		got, ok := ParseClockOffset(in)
		if !ok || int64(got.Seconds()) != want {
			t.Errorf("%q: %v %v, want %ds", in, got, ok, want)
		}
	}
	for _, bad := range []string{"3 minutes", "180", "about right", "3 minutes ahead and behind", "+3m behind", "fast"} {
		if got, ok := ParseClockOffset(bad); ok {
			t.Errorf("%q accepted as %v", bad, got)
		}
	}
}
