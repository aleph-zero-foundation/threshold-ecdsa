package zkpok

//ZKproof is a base interface for ZK proofs
type ZKproof interface {
	Verify() bool
	Marshal() []byte
	Unmarshal([]byte) ZKproof
}
