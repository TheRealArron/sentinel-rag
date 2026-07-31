package parser

import (
	"testing"
	"time"
)

func TestParseRFC3164(t *testing.T) {
	freezeClock(t, time.UTC)

	env := Parse("Jul 30 05:30:12 sentinel sshd[4021]: Failed password for root from 203.0.113.45 port 51234 ssh2")

	if env.Format != "rfc3164" {
		t.Fatalf("Format = %q, want rfc3164", env.Format)
	}
	if env.Host != "sentinel" || env.Process != "sshd" || env.PID != 4021 {
		t.Errorf("host/process/pid = %q/%q/%d", env.Host, env.Process, env.PID)
	}
	if env.Message != "Failed password for root from 203.0.113.45 port 51234 ssh2" {
		t.Errorf("Message = %q", env.Message)
	}
	if !env.HasTime || env.Timestamp.Year() != 2026 || env.Timestamp.Month() != time.July {
		t.Errorf("Timestamp = %v", env.Timestamp)
	}
}

func TestParseRFC3164SingleDigitDay(t *testing.T) {
	// "Jul  3" (two spaces) and "Jul 30" must both parse. The reference clock is
	// pinned to a UTC location so this test isolates day parsing; the local-zone
	// normalisation it would otherwise be entangled with has its own test below.
	freezeClock(t, time.UTC)

	env := Parse("Jul  3 05:30:12 host cron[9]: (root) CMD (/usr/bin/true)")
	if !env.HasTime || env.Timestamp.Day() != 3 {
		t.Fatalf("day = %d, want 3 (HasTime=%v)", env.Timestamp.Day(), env.HasTime)
	}
}

func TestParseRFC3164UsesTheHostLocalZone(t *testing.T) {
	// RFC 3164 timestamps carry no timezone: syslog writes the host's local time.
	// The parser therefore reads them in the local zone and normalises to UTC.
	//
	// This is worth a dedicated test because the failure is invisible in CI. An
	// assertion like "day == 3" holds in UTC and breaks in Asia/Tokyo, so a
	// timezone-dependent test passes on the build server and fails only on the
	// developer's machine — which is exactly how it was found.
	tokyo, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	freezeClock(t, tokyo)

	env := Parse("Jul  3 05:30:12 host cron[9]: (root) CMD (/usr/bin/true)")
	if !env.HasTime {
		t.Fatal("HasTime = false")
	}

	want := time.Date(2026, time.July, 3, 5, 30, 12, 0, tokyo).UTC()
	if !env.Timestamp.Equal(want) {
		t.Fatalf("Timestamp = %v, want %v", env.Timestamp, want)
	}
	// 05:30 JST is 20:30 UTC on the previous day.
	if env.Timestamp.Day() != 2 || env.Timestamp.Hour() != 20 {
		t.Errorf("expected the UTC-normalised value to be day 2 at 20:00-ish, got %v", env.Timestamp)
	}
	if env.Timestamp.Location() != time.UTC {
		t.Errorf("Location = %v, want UTC", env.Timestamp.Location())
	}
}

// freezeClock pins parser.Now to a fixed instant in loc. The location matters:
// parseBSDTime resolves year-less timestamps against ref.Location().
func freezeClock(t *testing.T, loc *time.Location) {
	t.Helper()
	fixed := time.Date(2026, time.July, 30, 6, 0, 0, 0, loc)
	Now = func() time.Time { return fixed }
	t.Cleanup(func() { Now = func() time.Time { return time.Now() } })
}

func TestParseRFC3164WithPriority(t *testing.T) {
	env := Parse("<38>Jul 30 05:30:12 host sshd[1]: msg")
	// 38 = facility 4 (auth) * 8 + severity 6 (info)
	if env.Facility != "auth" || env.Severity != 6 {
		t.Errorf("facility/severity = %q/%d, want auth/6", env.Facility, env.Severity)
	}
}

func TestParseRFC5424(t *testing.T) {
	env := Parse(`<34>1 2026-07-30T05:30:12.003Z sentinel sudo 8123 ID47 - arron : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash`)
	if env.Format != "rfc5424" {
		t.Fatalf("Format = %q, want rfc5424", env.Format)
	}
	if env.Host != "sentinel" || env.Process != "sudo" || env.PID != 8123 {
		t.Errorf("host/process/pid = %q/%q/%d", env.Host, env.Process, env.PID)
	}
	if env.Facility != "auth" || env.Severity != 2 {
		t.Errorf("facility/severity = %q/%d, want auth/2", env.Facility, env.Severity)
	}
	if env.Message == "" || env.Timestamp.Second() != 12 {
		t.Errorf("message=%q ts=%v", env.Message, env.Timestamp)
	}
}

func TestParseISO8601(t *testing.T) {
	env := Parse("2026-07-30T05:30:12+09:00 sentinel kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.9")
	if env.Format != "iso8601" {
		t.Fatalf("Format = %q, want iso8601", env.Format)
	}
	if env.Host != "sentinel" || env.Process != "kernel" {
		t.Errorf("host/process = %q/%q", env.Host, env.Process)
	}
	// +09:00 05:30 is 20:30 UTC the previous day.
	if env.Timestamp.Hour() != 20 || env.Timestamp.Day() != 29 {
		t.Errorf("Timestamp not normalised to UTC: %v", env.Timestamp)
	}
}

func TestParseNoHostname(t *testing.T) {
	env := Parse("2026-07-30T05:30:12Z sshd[77]: Invalid user oracle from 198.51.100.7")
	if env.Process != "sshd" || env.PID != 77 {
		t.Errorf("process/pid = %q/%d, want sshd/77", env.Process, env.PID)
	}
	if env.Host != "" {
		t.Errorf("Host = %q, want empty", env.Host)
	}
}

func TestParseUnrecognisedFallsBackToRaw(t *testing.T) {
	env := Parse("this is not a syslog line at all")
	if env.Format != "raw" {
		t.Fatalf("Format = %q, want raw", env.Format)
	}
	if env.Message != "this is not a syslog line at all" {
		t.Errorf("Message = %q", env.Message)
	}
	if env.HasTime {
		t.Error("HasTime = true for a line with no timestamp")
	}
}

func TestResolveYearRollover(t *testing.T) {
	cases := []struct {
		name string
		msg  time.Month
		ref  time.Time
		want int
	}{
		{"same month", time.July, date(2026, time.July), 2026},
		{"one month ahead is skew", time.August, date(2026, time.July), 2026},
		{"december log read in january", time.December, date(2026, time.January), 2025},
		{"january log read in december", time.January, date(2026, time.December), 2027},
		{"earlier this year", time.March, date(2026, time.July), 2026},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveYear(tc.msg, tc.ref); got != tc.want {
				t.Errorf("resolveYear(%v, %v) = %d, want %d", tc.msg, tc.ref.Month(), got, tc.want)
			}
		})
	}
}

func date(y int, m time.Month) time.Time {
	return time.Date(y, m, 15, 12, 0, 0, 0, time.UTC)
}

func BenchmarkParse(b *testing.B) {
	line := "Jul 30 05:30:12 sentinel sshd[4021]: Failed password for root from 203.0.113.45 port 51234 ssh2"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Parse(line)
	}
}
