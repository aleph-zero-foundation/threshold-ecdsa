package zkpok

import (
	"encoding/gob"
	"io"
)

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
	Decode(ZKproof) error
}

type noopZKproof struct{}

// NewNoopZKProof constructs a trivial proof
func NewNoopZKProof() ZKproof { return &noopZKproof{} }

func (*noopZKproof) Verify() bool { return true }

type encoder struct {
	enc *gob.Encoder
}

// NewEncoder constructs an encoder for ZKproofs
func NewEncoder(w io.Writer) Encoder {
	return &encoder{gob.NewEncoder(w)}
}

func (e *encoder) Encode(zkp ZKproof) error {
	return e.enc.Encode(zkp)
}

type decoder struct {
	dec *gob.Decoder
}

// NewDecoder constructs a decoder for ZKproofs
func NewDecoder(r io.Reader) Decoder {
	return &decoder{gob.NewDecoder(r)}
}

func (d *decoder) Decode(zkp ZKproof) error {
	return d.dec.Decode(zkp)
}
