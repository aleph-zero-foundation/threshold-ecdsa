package zkpok

//ZKproof represents a zero-knowledge proof that may be verified
type ZKproof interface {
	Verify() bool
}

// NoopZKproof is a trivial proof that always returns true
type NoopZKproof struct{}

// Verify implements a ZKproof.Verify method
func (*NoopZKproof) Verify() bool { return true }

// MarshalBinary implements a method needed for encoding
func (NoopZKproof) MarshalBinary() ([]byte, error) { return []byte{}, nil }

// UnmarshalBinary implements a method needed for decoding
func (*NoopZKproof) UnmarshalBinary(_ []byte) error { return nil }
