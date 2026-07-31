// Package tail provides an io.Reader that follows a growing log file, surviving
// the two things logrotate does to a file underneath you: truncation in place
// (copytruncate) and replacement by a new inode (create).
package tail

import (
	"context"
	"io"
	"os"
	"time"
)

// Follower reads a file and blocks at EOF waiting for more data, like `tail -F`.
type Follower struct {
	ctx      context.Context
	path     string
	f        *os.File
	offset   int64
	poll     time.Duration
	openInfo os.FileInfo
}

// Follow opens path for following. When fromStart is false, reading begins at
// the current end of file, which is what you want when attaching to a live
// /var/log/auth.log: replaying months of history on every restart would flood
// the vector store with duplicates.
func Follow(ctx context.Context, path string, fromStart bool, poll time.Duration) (*Follower, error) {
	if poll <= 0 {
		poll = 250 * time.Millisecond
	}
	t := &Follower{ctx: ctx, path: path, poll: poll}
	if err := t.open(fromStart); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Follower) open(fromStart bool) error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	off := int64(0)
	if !fromStart {
		off = fi.Size()
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			f.Close()
			return err
		}
	}
	if t.f != nil {
		t.f.Close()
	}
	t.f, t.offset, t.openInfo = f, off, fi
	return nil
}

// Read implements io.Reader. It returns (0, ctx.Err()) when the context is
// cancelled and otherwise never returns io.EOF, because the file may still grow.
func (t *Follower) Read(p []byte) (int, error) {
	for {
		if err := t.ctx.Err(); err != nil {
			return 0, err
		}
		n, err := t.f.Read(p)
		if n > 0 {
			t.offset += int64(n)
			return n, nil
		}
		if err != nil && err != io.EOF {
			return 0, err
		}
		if err := t.checkRotation(); err != nil {
			return 0, err
		}
		select {
		case <-t.ctx.Done():
			return 0, t.ctx.Err()
		case <-time.After(t.poll):
		}
	}
}

// checkRotation reopens the file if it was truncated or replaced. A missing path
// is not an error: logrotate's window between rename and create is short, so we
// keep the old handle and retry on the next poll.
func (t *Follower) checkRotation() error {
	fi, err := os.Stat(t.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !os.SameFile(fi, t.openInfo) {
		return t.open(true) // new inode: read the replacement from its start
	}
	if fi.Size() < t.offset {
		return t.open(true) // truncated in place: rewind
	}
	return nil
}

// Close releases the underlying file.
func (t *Follower) Close() error {
	if t.f == nil {
		return nil
	}
	return t.f.Close()
}
