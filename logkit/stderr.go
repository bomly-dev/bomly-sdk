package logkit

import "io"

// CommandStderr counts subprocess stderr and optionally mirrors it to the
// caller's debug output. It does not retain the contents.
type CommandStderr struct {
	visible io.Writer
	debug   bool
	bytes   int64
}

// NewCommandStderr creates a subprocess stderr counter. When debug is true,
// writes are also forwarded to visible as they arrive.
func NewCommandStderr(visible io.Writer, debug bool) *CommandStderr {
	return &CommandStderr{visible: visible, debug: debug}
}

// Write records the byte count and mirrors the bytes when debug output is
// enabled.
func (w *CommandStderr) Write(p []byte) (int, error) {
	if w == nil {
		return len(p), nil
	}
	w.bytes += int64(len(p))
	if w.debug && w.visible != nil {
		return w.visible.Write(p)
	}
	return len(p), nil
}

// ByteCount returns the number of bytes written to subprocess stderr.
func (w *CommandStderr) ByteCount() int64 {
	if w == nil {
		return 0
	}
	return w.bytes
}
