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
	"encoding/hex"
	"errors"
	"math"
	"testing"
)

// stateHasher is the subset of [Hasher224] and [Hasher256] needed to exercise
// the serialized state guard against both hash variants.
type stateHasher interface {
	Write(b []byte) (int, error)
	SaveState(target []byte) []byte
	UnmarshalBinary(state []byte) error
}

// TestLoadStateRejectsOversizedNbuf ensures a serialized state whose buffered
// byte count is not within the partial block buffer is rejected rather than
// stored.  Storing it caused a subsequent write to index outside of the buffer
// and panic.
func TestLoadStateRejectsOversizedNbuf(t *testing.T) {
	variants := []struct {
		name    string                   // test description
		newHash func() stateHasher       // creates the hasher under test
		sum     func(stateHasher) string // finalizes to a hex-encoded checksum
	}{{
		name:    "BLAKE-256",
		newHash: func() stateHasher { return NewHasher256() },
		sum: func(h stateHasher) string {
			sum := h.(*Hasher256).Sum256()
			return hex.EncodeToString(sum[:])
		},
	}, {
		name:    "BLAKE-224",
		newHash: func() stateHasher { return NewHasher224() },
		sum: func(h stateHasher) string {
			sum := h.(*Hasher224).Sum224()
			return hex.EncodeToString(sum[:])
		},
	}}

	// Every buffered byte count from a full block upwards must be rejected, not
	// just the all ones value that a truncating implementation would wrap.
	nbufs := []uint32{BlockSize, BlockSize + 1, 1 << 16, math.MaxUint32}

	for _, variant := range variants {
		h := variant.newHash()
		_, _ = h.Write([]byte("some data that leaves a partial block"))
		good := h.SaveState(nil)

		for _, nbuf := range nbufs {
			bad := bytes.Clone(good)
			binary.BigEndian.PutUint32(bad[SavedStateSize-4:], nbuf)

			victim := variant.newHash()
			_, _ = victim.Write([]byte("original"))
			before := variant.sum(victim)

			err := victim.UnmarshalBinary(bad)
			if !errors.Is(err, ErrMalformedState) {
				t.Fatalf("%s: want ErrMalformedState for a buffered byte count "+
					"of %d, got %v", variant.name, nbuf, err)
			}
			if after := variant.sum(victim); after != before {
				t.Fatalf("%s: the receiver was mutated by a state that was "+
					"rejected", variant.name)
			}
		}

		// A valid state must still restore exactly.
		restored := variant.newHash()
		if err := restored.UnmarshalBinary(good); err != nil {
			t.Fatalf("%s: valid state rejected: %v", variant.name, err)
		}
		if variant.sum(restored) != variant.sum(h) {
			t.Fatalf("%s: valid state did not restore", variant.name)
		}
	}
}

// TestWriteLargeLengthGuard ensures the partial block guard is computed without
// truncating the write length to 32 bits.  A write whose length wraps to a
// small uint32 must still flush the pending partial block.
//
// The predicate is exercised directly because reproducing the truncation
// through [hasher.write] requires an actual 4 GiB slice.
func TestWriteLargeLengthGuard(t *testing.T) {
	if math.MaxInt < math.MaxUint32 {
		t.Skip("write lengths beyond 32 bits are not representable on this platform")
	}

	// wrap is the smallest write length that truncates to zero in 32 bits.
	const wrap = 1 << 32

	tests := []struct {
		name string // test description
		nbuf uint32 // number of bytes already buffered
		n    uint64 // number of bytes being written
		want bool   // expected result
	}{{
		name: "no pending partial block",
		nbuf: 0,
		n:    BlockSize,
		want: false,
	}, {
		name: "pending partial block left unfilled",
		nbuf: 1,
		n:    BlockSize - 2,
		want: false,
	}, {
		name: "pending partial block exactly filled",
		nbuf: 1,
		n:    BlockSize - 1,
		want: true,
	}, {
		name: "pending partial block overfilled",
		nbuf: BlockSize - 1,
		n:    2,
		want: true,
	}, {
		name: "empty write with a pending partial block",
		nbuf: BlockSize - 1,
		n:    0,
		want: false,
	}, {
		name: "write length truncating to zero in 32 bits",
		nbuf: 1,
		n:    wrap,
		want: true,
	}, {
		name: "write length truncating below a block in 32 bits",
		nbuf: 1,
		n:    wrap + 1,
		want: true,
	}, {
		name: "write length truncating to zero without a pending block",
		nbuf: 0,
		n:    wrap,
		want: false,
	}}

	for _, test := range tests {
		// Note the length is converted here rather than in the table so the
		// constants remain representable when an int is 32 bits.
		got := needsPartialBlockFlush(test.nbuf, int(test.n))
		if got != test.want {
			t.Errorf("%q: unexpected result -- got %v, want %v", test.name, got,
				test.want)
		}
	}
}

// TestWriteSplitAcrossPartialBlock ensures hashing the same bytes in a single
// write and in two writes split across a partial block boundary agree.
func TestWriteSplitAcrossPartialBlock(t *testing.T) {
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
