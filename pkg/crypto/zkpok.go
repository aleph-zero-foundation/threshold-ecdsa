package zkpok

//ZKproof represents a zero-knowledge proof that may be verified
type ZKproof interface {
	Verify() bool
}

// Encoder represents encoding.Encoder for zkproofs
type Encoder interface {
	Encode(ZKproof) error
}

// Decoder represents encoding.Decoder for zkproofs
type Decoder interface {
	Decode() (ZKproof, error)
}
