package logkit

import (
	"bytes"
	"strings"
	"testing"
)

func TestCommandStderrCountsAndMirrorsInDebug(t *testing.T) {
	var visible bytes.Buffer
	writer := NewCommandStderr(&visible, true)
	if _, err := writer.Write([]byte("warn: noisy stderr\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if got := writer.ByteCount(); got != int64(len("warn: noisy stderr\n")) {
		t.Fatalf("ByteCount() = %d", got)
	}
	if !strings.Contains(visible.String(), "warn: noisy stderr") {
		t.Fatalf("expected debug writer mirroring, got %q", visible.String())
	}
}

func TestCommandStderrNilAndHidden(t *testing.T) {
	var writer *CommandStderr
	if _, err := writer.Write([]byte("ignored")); err != nil {
		t.Fatalf("nil Write() error = %v", err)
	}

	var visible bytes.Buffer
	hidden := NewCommandStderr(&visible, false)
	if _, err := hidden.Write([]byte("secret\n")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if visible.Len() != 0 {
		t.Fatalf("expected hidden writer not to mirror output, got %q", visible.String())
	}
}
