// language: Go, file: internal/router/discover_test.go
package router

import (
	"encoding/json"
	"testing"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
)

// decode is a helper for building a payload from JSON source.
func decode(t *testing.T, src string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(src), &v); err != nil {
		t.Fatalf("bad test fixture: %v", err)
	}
	return v
}

// TestWalkDevicesFindsNestedRecords covers the shapes routers actually return:
// a bare array, a wrapper object, and a device list nested two levels deep.
func TestWalkDevicesFindsNestedRecords(t *testing.T) {
	cases := map[string]string{
		"bare array": `[
			{"mac":"aa:bb:cc:dd:ee:01","ip":"192.168.1.10"},
			{"mac":"aa:bb:cc:dd:ee:02","ip":"192.168.1.11"}
		]`,
		"wrapped": `{"hosts":[{"mac":"aa:bb:cc:dd:ee:01"},{"mac":"aa:bb:cc:dd:ee:02"}]}`,
		"nested": `{"data":{"Hosts":{"hostList":[
			{"mac":"aa:bb:cc:dd:ee:01"},{"mac":"aa:bb:cc:dd:ee:02"}]}}}`,
		"key variants": `{"list":[
			{"macAddress":"aa:bb:cc:dd:ee:01"},
			{"mac_addr":"aa:bb:cc:dd:ee:02"},
			{"MAC":"aa:bb:cc:dd:ee:03"},
			{"hwaddr":"aa:bb:cc:dd:ee:04"},
			{"physicalAddress":"aa:bb:cc:dd:ee:05"}]}`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			got := walkDevices(decode(t, src))
			if len(got) < 2 {
				t.Fatalf("found %d device records, want at least 2", len(got))
			}
		})
	}
}

func TestWalkDevicesIgnoresNonDevices(t *testing.T) {
	// A response full of metadata and no MACs must yield nothing, rather than
	// inventing devices from unrelated objects.
	src := `{"error":"0","system":{"model":"HG8145V5","serial":"ABC123"},
		"wifi":{"ssid":"HomeNet","channel":6,"enabled":true}}`
	if got := walkDevices(decode(t, src)); len(got) != 0 {
		t.Fatalf("found %d records in a response with no MACs: %+v", len(got), got)
	}
}

func TestWalkDevicesRejectsInvalidMACs(t *testing.T) {
	src := `{"hosts":[
		{"mac":"00:00:00:00:00:00"},
		{"mac":"ff:ff:ff:ff:ff:ff"},
		{"mac":"01:00:5e:00:00:01"},
		{"mac":"not-a-mac"},
		{"mac":"aa:bb:cc:dd:ee:01"}
	]}`
	got := walkDevices(decode(t, src))
	if len(got) != 1 {
		t.Fatalf("found %d records, want exactly 1 (the valid unicast MAC)", len(got))
	}
}

func TestWalkDevicesDeduplicates(t *testing.T) {
	// The same client appearing under two sections must collapse to one.
	src := `{"wifi":[{"mac":"aa:bb:cc:dd:ee:01"}],"lan":[{"mac":"AA-BB-CC-DD-EE-01"}]}`
	got := walkDevices(decode(t, src))
	if len(got) != 1 {
		t.Fatalf("found %d records, want 1 after de-duplication", len(got))
	}
}

// TestConnectionFromWireless is the case the feature exists for: a device
// associated over Wi-Fi must be labelled wlan with its SSID.
func TestConnectionFromWireless(t *testing.T) {
	rec := decode(t, `{
		"mac":"aa:bb:cc:dd:ee:01",
		"ip":"192.168.1.10",
		"interfaceType":"WLAN",
		"ssid":"HomeNet-2.4G",
		"band":"2.4G",
		"rate":"72Mbps",
		"rssi":"-58 dBm"
	}`).(map[string]any)

	c := connectionFrom(rec)
	if c.Kind != model.LinkWLAN {
		t.Fatalf("kind = %q, want wlan", c.Kind)
	}
	if c.Detail != "HomeNet-2.4G" {
		t.Errorf("ssid = %q, want HomeNet-2.4G", c.Detail)
	}
	if c.Band != "2.4G" {
		t.Errorf("band = %q, want 2.4G", c.Band)
	}
	if c.Signal != "-58 dBm" {
		t.Errorf("signal = %q, want -58 dBm", c.Signal)
	}
	if c.Source != "router" {
		t.Errorf("source = %q, want router", c.Source)
	}
	if c.Label() == "" {
		t.Error("Label() is empty for a fully-populated wireless connection")
	}
}

// TestConnectionFromWired covers the LAN port case.
func TestConnectionFromWired(t *testing.T) {
	cases := []struct {
		name string
		src  string
		port string
	}{
		{"explicit port", `{"mac":"aa:bb:cc:dd:ee:02","interfaceType":"LAN","port":"LAN1"}`, "LAN1"},
		{"numeric port", `{"mac":"aa:bb:cc:dd:ee:02","interfaceType":"Ethernet","lanPort":"2"}`, "LAN2"},
		{"port in free text", `{"mac":"aa:bb:cc:dd:ee:02","interface":"ethernet lan3","port":"lan3"}`, "LAN3"},
		{"eth naming", `{"mac":"aa:bb:cc:dd:ee:02","linkType":"wired","portName":"eth4"}`, "LAN4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := decode(t, tc.src).(map[string]any)
			c := connectionFrom(rec)
			if c.Kind != model.LinkLAN {
				t.Fatalf("kind = %q, want lan", c.Kind)
			}
			if c.Port != tc.port {
				t.Errorf("port = %q, want %q", c.Port, tc.port)
			}
		})
	}
}

// TestConnectionFromIsHonestAboutUnknown is the important negative case.
// A record with nothing conclusive must not claim a link type, because a wrong
// label is worse than no label: it would tell the operator a device is wired
// when it is not.
func TestConnectionFromIsHonestAboutUnknown(t *testing.T) {
	rec := decode(t, `{"mac":"aa:bb:cc:dd:ee:03","ip":"192.168.1.12"}`).(map[string]any)
	c := connectionFrom(rec)
	if c.Kind != "" && c.Kind != model.LinkUnknown {
		t.Fatalf("claimed kind %q with no evidence in the record", c.Kind)
	}
	if c.Label() != "" {
		t.Fatalf("Label() = %q, want empty when nothing is known", c.Label())
	}
}

// TestSSIDImpliesWireless: a record naming an SSID is on Wi-Fi even if the
// router did not say so explicitly.
func TestSSIDImpliesWireless(t *testing.T) {
	rec := decode(t, `{"mac":"aa:bb:cc:dd:ee:04","ssid":"Guest"}`).(map[string]any)
	if c := connectionFrom(rec); c.Kind != model.LinkWLAN {
		t.Fatalf("kind = %q, want wlan (an SSID is present)", c.Kind)
	}
}

func TestNormaliseBand(t *testing.T) {
	cases := []struct {
		band, raw string
		channel   any
		want      string
	}{
		{"2.4G", "", nil, "2.4G"},
		{"5G", "", nil, "5G"},
		{"2.4 GHz", "", nil, "2.4G"},
		{"", "radio0 5ghz", nil, "5G"},
		{"", "", float64(6), "2.4G"},
		{"", "", float64(44), "5G"},
		{"", "", nil, ""},
	}
	for _, tc := range cases {
		m := map[string]any{}
		if tc.channel != nil {
			m["channel"] = tc.channel
		}
		if got := normaliseBand(tc.band, tc.raw, m); got != tc.want {
			t.Errorf("normaliseBand(%q,%q,ch=%v) = %q, want %q",
				tc.band, tc.raw, tc.channel, got, tc.want)
		}
	}
}

func TestNormalisePort(t *testing.T) {
	cases := map[string]string{
		"LAN1": "LAN1", "lan1": "LAN1", "1": "LAN1", "ETH2": "LAN2",
		"ethernet3": "LAN3", "port4": "LAN4", "": "",
	}
	for in, want := range cases {
		if got := normalisePort(in, ""); got != want {
			t.Errorf("normalisePort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormaliseRate(t *testing.T) {
	cases := map[string]string{
		"72":       "72 Mbps",
		"72Mbps":   "72 Mbps",
		"72 Mbps":  "72 Mbps",
		"144.4":    "144.4 Mbps", // the decimal is meaningful, keep it
		"1000":     "1000 Mbps",
		"866 Mbps": "866 Mbps",
		"300M":     "300 M",
		"54kbps":   "54 kbps",
		"1Gbps":    "1 Gbps",
		"":         "",
	}
	for in, want := range cases {
		if got := normaliseRate(in); got != want {
			t.Errorf("normaliseRate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormaliseSignal(t *testing.T) {
	cases := map[string]string{
		"-58":     "-58 dBm",
		"-58 dBm": "-58 dBm",
		"80%":     "80%",
		"75":      "75%",
		"":        "",
	}
	for in, want := range cases {
		if got := normaliseSignal(in); got != want {
			t.Errorf("normaliseSignal(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestInterpretLogin covers the inconsistent ways a gateway reports a rejected
// credential. Getting this wrong means either a false success or a false
// failure, so each shape is pinned.
func TestInterpretLogin(t *testing.T) {
	ok := []string{
		`{"error":"0"}`,
		`{"error":0}`,
		`{"errcode":0,"sysauth":"abc123"}`,
		`{"result":"ok"}`,
		`{"success":true}`,
		`{}`,
		`{"errorCategory":"ok"}`,
	}
	for _, src := range ok {
		if err := interpretLogin(decode(t, src).(map[string]any)); err != nil {
			t.Errorf("interpretLogin(%s) = %v, want success", src, err)
		}
	}

	bad := []string{
		`{"error":"1"}`,
		`{"error":1}`,
		`{"errcode":108001}`,
		`{"result":"error"}`,
		`{"success":false}`,
		`{"errorCategory":"auth_error"}`,
	}
	for _, src := range bad {
		if err := interpretLogin(decode(t, src).(map[string]any)); err == nil {
			t.Errorf("interpretLogin(%s) = nil, want a failure", src)
		}
	}

	// A gateway asking for a challenge must be distinguishable, because that
	// is what triggers the salted retry.
	if err := interpretLogin(decode(t, `{"error":"challenge_required"}`).(map[string]any)); err != errChallengeRequired {
		t.Errorf("a challenge request was not detected: %v", err)
	}
}

func TestFirstIPv4(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{`{"mac":"aa:bb:cc:dd:ee:01","ip":"192.168.1.10"}`, "192.168.1.10"},
		{`{"mac":"aa:bb:cc:dd:ee:01","ipAddress":"10.0.0.5"}`, "10.0.0.5"},
		{`{"mac":"aa:bb:cc:dd:ee:01"}`, ""},
		{`{"mac":"aa:bb:cc:dd:ee:01","ip":"fe80::1"}`, ""},
	}
	for _, tc := range cases {
		if got := firstIPv4(decode(t, tc.src).(map[string]any)); got != tc.want {
			t.Errorf("firstIPv4(%s) = %q, want %q", tc.src, got, tc.want)
		}
	}
}

func TestLooksLikeMAC(t *testing.T) {
	good := []string{"aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF"}
	for _, s := range good {
		if !looksLikeMAC(s) {
			t.Errorf("looksLikeMAC(%q) = false, want true", s)
		}
	}
	bad := []string{"", "aa:bb:cc:dd:ee", "zz:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff:00",
		"192.168.1.1", "hello world!!!!!"}
	for _, s := range bad {
		if looksLikeMAC(s) {
			t.Errorf("looksLikeMAC(%q) = true, want false", s)
		}
	}
}

// TestClassifyLink pins the agent-side classification, including the ordering
// trap: "vEthernet (WSL)" contains both "ethernet" and a virtual marker, and
// must resolve to virtual.
func TestClassifyLink(t *testing.T) {
	cases := []struct {
		name, desc string
		want       model.LinkKind
	}{
		{"Wi-Fi", "Intel(R) Wi-Fi 6 AX201 160MHz", model.LinkWLAN},
		{"wlan0", "Wireless Network Adapter", model.LinkWLAN},
		{"Ethernet", "Realtek PCIe GbE Family Controller", model.LinkLAN},
		{"eth0", "", model.LinkLAN},
		{"vEthernet (WSL (Hyper-V firewall))", "Hyper-V Virtual Ethernet Adapter #2", model.LinkVirtual},
		{"Ethernet 2", "VirtualBox Host-Only Ethernet Adapter", model.LinkVirtual},
		{"docker0", "", model.LinkVirtual},
		{"Loopback Pseudo-Interface 1", "", model.LinkVirtual},
		{"OpenVPN Connect DCO Adapter", "OpenVPN Data Channel Offload", model.LinkVirtual},
		{"Mystery", "Unknown Thing", model.LinkUnknown},
	}
	for _, tc := range cases {
		if got := model.ClassifyLink(tc.name, tc.desc); got != tc.want {
			t.Errorf("ClassifyLink(%q,%q) = %q, want %q", tc.name, tc.desc, got, tc.want)
		}
	}
}

func TestConfigEnabled(t *testing.T) {
	cases := []struct {
		backend, host string
		want          bool
	}{
		{"auto", "192.168.1.1", true},
		{"huawei", "192.168.1.1", true},
		{"none", "192.168.1.1", false},
		{"auto", "", false},
		{"", "192.168.1.1", false},
	}
	for _, tc := range cases {
		c := Config{Backend: tc.backend, Host: tc.host}
		if got := c.Enabled(); got != tc.want {
			t.Errorf("Enabled(backend=%q,host=%q) = %v, want %v",
				tc.backend, tc.host, got, tc.want)
		}
	}
}

func TestNormaliseHost(t *testing.T) {
	cases := map[string]string{
		"192.168.1.1":          "http://192.168.1.1",
		"http://192.168.1.1":   "http://192.168.1.1",
		"http://192.168.1.1/":  "http://192.168.1.1",
		"https://router.local": "https://router.local",
		" 192.168.1.1 ":        "http://192.168.1.1",
	}
	for in, want := range cases {
		if got := normaliseHost(in); got != want {
			t.Errorf("normaliseHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidMAC(t *testing.T) {
	good := []string{"aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "00:11:22:33:44:55"}
	for _, s := range good {
		if !validMAC(s) {
			t.Errorf("validMAC(%q) = false, want true", s)
		}
	}
	bad := []string{"", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff",
		"01:00:5e:00:00:01", "aa:bb:cc:dd:ee", "not-a-mac"}
	for _, s := range bad {
		if validMAC(s) {
			t.Errorf("validMAC(%q) = true, want false", s)
		}
	}
}

// TestConnectionLabel covers what the operator actually reads in the table.
func TestConnectionLabel(t *testing.T) {
	cases := []struct {
		c    model.Connection
		want string
	}{
		{model.Connection{Kind: model.LinkWLAN, Detail: "HomeNet-5G", Band: "5G"}, "wlan · HomeNet-5G (5G)"},
		{model.Connection{Kind: model.LinkWLAN, Detail: "HomeNet-2.4G"}, "wlan · HomeNet-2.4G"},
		{model.Connection{Kind: model.LinkWLAN}, "wlan"},
		{model.Connection{Kind: model.LinkLAN, Port: "LAN1"}, "lan · LAN1"},
		{model.Connection{Kind: model.LinkLAN}, "lan"},
		{model.Connection{Kind: model.LinkUnknown}, ""},
		{model.Connection{}, ""},
	}
	for _, tc := range cases {
		if got := tc.c.Label(); got != tc.want {
			t.Errorf("Label(%+v) = %q, want %q", tc.c, got, tc.want)
		}
	}
}
