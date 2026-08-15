// Copyright (c) 2026 github.com/go-webauthn authors.
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//
// This file has no upstream counterpart.  It covers the fixes this fork carries
// on top of the upstream sources, which are described in the repository README.

package blake256

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// TestLoadStateRejectsOversizedNbuf ensures a serialized state whose buffered
// byte count is not within the partial block buffer is rejected rather than
// stored.  Storing it caused a subsequent write to index outside of the buffer
// and panic.
func TestLoadStateRejectsOversizedNbuf(t *testing.T) {
	h := NewHasher256()
	_, _ = h.Write([]byte("some data that leaves a partial block"))
	good := h.SaveState(nil)

	bad := bytes.Clone(good)
	binary.BigEndian.PutUint32(bad[SavedStateSize-4:], 0xFFFFFFFF)

	victim := NewHasher256()
	_, _ = victim.Write([]byte("original"))
	before := victim.Sum256()

	err := victim.UnmarshalBinary(bad)
	if !errors.Is(err, ErrMalformedState) {
		t.Fatalf("want ErrMalformedState for an oversized buffered byte count, got %v", err)
	}
	if after := victim.Sum256(); after != before {
		t.Fatal("the receiver was mutated by a state that was rejected")
	}

	// A valid state must still restore exactly.
	restored := NewHasher256()
	if err := restored.UnmarshalBinary(good); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}
	if restored.Sum256() != h.Sum256() {
		t.Fatal("valid state did not restore")
	}
}

// TestWriteLargeLengthGuard ensures the partial block guard is computed without
// truncating the length to 32 bits.  Writing a slice whose length wraps to a
// small uint32 must still flush the pending partial block.
func TestWriteLargeLengthGuard(t *testing.T) {
	// Hashing the same bytes in one write and in two writes split across a
	// partial block boundary must agree.
	data := bytes.Repeat([]byte{0xa5}, 3*64+7)

	oneShot := NewHasher256()
	_, _ = oneShot.Write(data)

	split := NewHasher256()
	_, _ = split.Write(data[:5])
	_, _ = split.Write(data[5:])

	if oneShot.Sum256() != split.Sum256() {
		t.Fatal("split writes across a partial block produced a different hash")
	}
}
