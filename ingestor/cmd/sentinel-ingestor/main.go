// Command sentinel-ingestor reads raw Linux logs and emits enriched,
// newline-delimited JSON events for the Sentinel RAG AI engine.
//
//	# one-shot: parse a file
//	sentinel-ingestor -in /var/log/auth.log -out data/events.jsonl -stats
//
//	# live: follow the journal-backed syslog, only medium+ severity
//	sentinel-ingestor -in /var/log/syslog -follow -min-score 40 | \
//	    python -m sentinel.ingest --stdin
//
//	# pipe mode
//	journalctl -f -o short-iso | sentinel-ingestor -in - -out -
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/TheRealArron/sentinel-rag/ingestor/internal/correlate"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/honeytoken"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/pipeline"
	"github.com/TheRealArron/sentinel-rag/ingestor/internal/sink"
)

// version is overridden at build time:
//
//	go build -ldflags "-X main.version=$(git describe --tags --always)"
var version = "dev"

func main() {
	if err := run(); err != nil {
		if errors.Is(err, context.Canceled) {
			// Ctrl-C / SIGTERM during -follow is a normal shutdown.
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "sentinel-ingestor: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		in         = flag.String("in", "-", `input log file, or "-" for stdin`)
		out        = flag.String("out", "-", `output JSONL file, or "-" for stdout`)
		workers    = flag.Int("workers", runtime.NumCPU(), "parser worker goroutines")
		minScore   = flag.Int("min-score", 0, "drop events scoring below this (0-100)")
		maxLine    = flag.Int("max-line", 8192, "maximum bytes kept per log line")
		keepRaw    = flag.Bool("raw", false, "include the sanitised raw line on each event")
		follow     = flag.Bool("follow", false, "keep reading as the file grows (tail -F)")
		fromStart  = flag.Bool("from-start", false, "with -follow, start at the beginning of the file")
		noCorr     = flag.Bool("no-correlate", false, "disable stateful incident correlation")
		bfThresh   = flag.Int("brute-threshold", 5, "auth failures from one source that trigger a brute-force incident")
		bfWindow   = flag.Duration("brute-window", time.Minute, "sliding window for the brute-force threshold")
		bfCooldown = flag.Duration("brute-cooldown", 5*time.Minute, "minimum gap between repeat incidents for one source")
		honeyPath  = flag.String("honeytokens", defaultHoneytokenPath, "canary username/path config (JSON); see config/honeytokens.json")
		honeyCheck = flag.String("honeytokens-verify", "", "verify canaries against a passwd file (use /etc/passwd, on the host) and exit")
		stats      = flag.Bool("stats", false, "print a run summary to stderr as JSON")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("sentinel-ingestor %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return nil
	}
	if *minScore < 0 || *minScore > 100 {
		return fmt.Errorf("-min-score must be between 0 and 100, got %d", *minScore)
	}

	tokens, err := loadHoneytokens(*honeyPath, flagWasSet("honeytokens"))
	if err != nil {
		return err
	}
	if *honeyCheck != "" {
		return verifyHoneytokens(tokens, *honeyCheck)
	}
	// The armed-canaries banner goes to stderr, which is also where -stats writes
	// its JSON report. Printing both would make `2>report.json` unparseable, so
	// in -stats mode the same facts are carried inside the JSON instead. stderr
	// stays machine-readable in exactly the mode meant for machines.
	if tokens.Len() > 0 && !*stats {
		fmt.Fprintf(os.Stderr, "sentinel-ingestor: %d honeytoken(s) armed from %s: %s\n",
			tokens.Len(), tokens.Path(), tokens.Summary())
	}

	// SIGINT/SIGTERM cancel the context so -follow shuts down cleanly and the
	// output buffer still gets flushed.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reader, closeReader, err := openInput(ctx, *in, *follow, *fromStart)
	if err != nil {
		return err
	}
	defer closeReader()

	writer, closeWriter, err := openOutput(*out)
	if err != nil {
		return err
	}
	defer closeWriter()

	js := sink.NewJSONL(writer)

	// In follow mode the consumer wants events as they happen, not when a 256 KiB
	// buffer fills, so flush on a ticker.
	if *follow {
		done := make(chan struct{})
		defer close(done)
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-ctx.Done():
					return
				case <-t.C:
					_ = js.Flush()
				}
			}
		}()
	}

	st, runErr := pipeline.Run(ctx, reader, js, pipeline.Options{
		Workers:            *workers,
		MaxLineLen:         *maxLine,
		MinScore:           *minScore,
		IncludeRaw:         *keepRaw,
		DisableCorrelation: *noCorr,
		Honeytokens:        tokens,
		Correlation: correlate.Config{
			FailureThreshold: *bfThresh,
			Window:           *bfWindow,
			Cooldown:         *bfCooldown,
		},
	})

	if *stats {
		enc := json.NewEncoder(os.Stderr)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			pipeline.Stats
			Version          string `json:"version"`
			Workers          int    `json:"workers"`
			HoneytokensArmed int    `json:"honeytokens_armed"`
			HoneytokensPath  string `json:"honeytokens_path,omitempty"`
		}{st, version, *workers, tokens.Len(), tokens.Path()})
	}
	return runErr
}

func openInput(ctx context.Context, path string, follow, fromStart bool) (io.Reader, func(), error) {
	if path == "-" {
		if follow {
			return nil, nil, errors.New("-follow requires a file path, not stdin")
		}
		return os.Stdin, func() {}, nil
	}
	if follow {
		f, err := tailFollow(ctx, path, fromStart)
		if err != nil {
			return nil, nil, fmt.Errorf("follow %s: %w", path, err)
		}
		return f, func() { _ = f.Close() }, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "-" {
		return os.Stdout, func() {}, nil
	}
	// Append rather than truncate: the Python side may already be tailing this
	// file, and re-running the ingestor should not silently erase its backlog.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s for write: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// defaultHoneytokenPath is looked for relative to the working directory. When the
// flag is left at this default and the file is absent, deception detection is
// simply off — a fresh clone should not fail to start over an optional feature.
// When the flag is set explicitly and the file is missing, that is an error: the
// operator asked for canaries and must not be left believing they are armed.
// Same auto-versus-explicit contract the Python engine uses for its backends.
const defaultHoneytokenPath = "config/honeytokens.json"

func flagWasSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func loadHoneytokens(path string, explicit bool) (*honeytoken.Set, error) {
	if path == "" {
		return nil, nil
	}
	set, err := honeytoken.Load(path)
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return set, nil
}

// verifyHoneytokens refuses to let a canary that collides with a real account go
// unnoticed. A colliding canary fires on every legitimate login, trains the
// operator to ignore it, and -- because this detector is wired to the firewall --
// can get a real user blocked.
func verifyHoneytokens(set *honeytoken.Set, passwdPath string) error {
	if set.Len() == 0 {
		fmt.Fprintln(os.Stderr, "no honeytokens configured")
		return nil
	}
	collisions, err := set.VerifyAgainstPasswd(passwdPath)
	if err != nil {
		return err
	}
	if len(collisions) > 0 {
		return fmt.Errorf("%d honeytoken(s) collide with real accounts in %s: %v -- "+
			"these would fire on legitimate logins; rename them", len(collisions), passwdPath, collisions)
	}
	fmt.Fprintf(os.Stderr, "ok: none of the %d honeytoken(s) exist in %s\n", set.Len(), passwdPath)
	return nil
}
