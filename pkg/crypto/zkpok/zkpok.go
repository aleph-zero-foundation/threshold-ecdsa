package zkpok

import "io"

//ZKproof represents a zero-knowledge proof that may be verified
type ZKproof interface {
	Verify() bool
	Encode(w io.Writer) error
}

// NoopZKproof is a trivial proof that always returns true
type NoopZKproof struct{}

// Verify implements a ZKproof.Verify method
func (NoopZKproof) Verify() bool { return true }

// Encode implements a method needed for encoding
func (NoopZKproof) Encode(_ io.Writer) error { return nil }

// Decode implements a method needed for decoding
func (*NoopZKproof) Decode(_ io.Reader) error { return nil }
