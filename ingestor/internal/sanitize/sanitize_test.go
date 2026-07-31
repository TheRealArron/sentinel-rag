package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLineEscapesEmbeddedNewline(t *testing.T) {
	// The classic log-forging payload: an attacker-chosen SSH username that
	// tries to close the current record and open a fake one.
	raw := "Failed password for invalid user admin\nJul 30 05:31:00 host sshd[1]: Accepted password for root"
	got := Line(raw, 0)

	if strings.ContainsAny(got.Clean, "\n\r") {
		t.Fatalf("newline survived sanitisation: %q", got.Clean)
	}
	if !strings.Contains(got.Clean, `\x0a`) {
		t.Errorf("expected escaped newline in %q", got.Clean)
	}
	if !got.HadControl || !got.Modified {
		t.Errorf("HadControl=%v Modified=%v, want both true", got.HadControl, got.Modified)
	}
}

func TestLineStripsANSIEscapes(t *testing.T) {
	cases := []struct{ name, raw, want string }{
		{"csi colour", "user=\x1b[31mroot\x1b[0m", "user=root"},
		{"csi erase", "before\x1b[2Kafter", "beforeafter"},
		{"osc hyperlink", "click\x1b]8;;http://evil\x07here\x1b]8;;\x07", "clickhere"},
		{"two byte", "a\x1b=b", "ab"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Line(tc.raw, 0)
			if got.Clean != tc.want {
				t.Errorf("Clean = %q, want %q", got.Clean, tc.want)
			}
			if !got.HadEscape {
				t.Error("HadEscape = false, want true")
			}
		})
	}
}

func TestLineStripsTrojanSourceBidi(t *testing.T) {
	// U+202E (RLO) makes the rendered text disagree with the byte order.
	raw := "sudo COMMAND=/bin/‮gnp‬ /etc/shadow"
	got := Line(raw, 0)
	if strings.ContainsRune(got.Clean, 0x202e) {
		t.Fatalf("bidi override survived: %q", got.Clean)
	}
	if !got.HadBidi {
		t.Error("HadBidi = false, want true")
	}
}

func TestLinePreservesJapanese(t *testing.T) {
	raw := "JPCERT/CC 注意喚起: SSHブルートフォース攻撃の増加について"
	got := Line(raw, 0)
	if got.Clean != raw {
		t.Errorf("Japanese text was altered:\n got %q\nwant %q", got.Clean, raw)
	}
	if got.Modified {
		t.Error("Modified = true for clean multibyte input")
	}
}

func TestLineTruncatesOnRuneBoundary(t *testing.T) {
	raw := strings.Repeat("日", 5000) // 3 bytes each
	got := Line(raw, 256)
	if len(got.Clean) > 256 {
		t.Errorf("len = %d, want <= 256", len(got.Clean))
	}
	if !got.Truncated {
		t.Error("Truncated = false, want true")
	}
	if !strings.HasSuffix(got.Clean, truncationMarker) {
		t.Errorf("missing truncation marker: %q", got.Clean)
	}
	for _, r := range got.Clean {
		if r == '�' {
			t.Fatal("truncation split a multibyte rune")
		}
	}
}

func TestLineRepairsInvalidUTF8(t *testing.T) {
	got := Line("valid\xff\xfetail", 0)
	if !got.HadInvalidUTF8 {
		t.Error("HadInvalidUTF8 = false, want true")
	}
	if !strings.Contains(got.Clean, "valid") || !strings.Contains(got.Clean, "tail") {
		t.Errorf("surrounding text lost: %q", got.Clean)
	}
}

func TestLineLeavesCleanInputUntouched(t *testing.T) {
	raw := "Jul 30 05:30:00 sentinel sshd[4021]: Accepted publickey for arron from 192.168.1.20 port 51234 ssh2"
	got := Line(raw, 0)
	if got.Modified || got.Clean != raw {
		t.Errorf("clean line was modified: %q", got.Clean)
	}
}

func TestLineTabBecomesSpace(t *testing.T) {
	got := Line("a\tb", 0)
	if got.Clean != "a b" {
		t.Errorf("Clean = %q, want %q", got.Clean, "a b")
	}
}

func FuzzLine(f *testing.F) {
	f.Add("Jul 30 05:30:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22")
	f.Add("\x1b[31m‮\x00\xff日本語")
	f.Fuzz(func(t *testing.T, raw string) {
		got := Line(raw, 512)
		if len(got.Clean) > 512 {
			t.Fatalf("length cap violated: %d", len(got.Clean))
		}
		if strings.ContainsAny(got.Clean, "\n\r\x00\x1b") {
			t.Fatalf("dangerous byte survived: %q", got.Clean)
		}
		// Sanitised output must always be valid UTF-8 so the JSON encoder and
		// the Python side never see broken bytes.
		if !utf8.ValidString(got.Clean) {
			t.Fatalf("output is not valid UTF-8: %q", got.Clean)
		}
	})
}
