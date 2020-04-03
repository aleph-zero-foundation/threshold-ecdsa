package crypto

//ZKproof Base interface for ZK proofs
type ZKproof interface {
	Verify() bool
	Marshal() []byte
	Unmarshal([]byte) ZKproof
}

//ZKeg a
type ZKeg struct {
}

//Verify a
func (p ZKeg) Verify() bool {
	return true
}

//Marshal a
func (p ZKeg) Marshal() []byte {
	return nil
}

//Unmarshal a
func (p ZKeg) Unmarshal(b []byte) ZKproof {
	return p
}

//CreateZKeg a
func CreateZKeg() ZKproof {
	return ZKeg{}
}

//ZKegReveal a
type ZKegReveal struct {
}

//Verify a
func (p ZKegReveal) Verify() bool {
	return true
}

//Marshal a
func (p ZKegReveal) Marshal() []byte {
	return nil
}

//Unmarshal a
func (p ZKegReveal) Unmarshal(b []byte) ZKproof {
	return p
}

//CreateZKegReveal a
func CreateZKegReveal() ZKproof {
	return ZKegReveal{}
}

//ZKre a
type ZKre struct {
}

//Verify a
func (p ZKre) Verify() bool {
	return true
}

//Marshal a
func (p ZKre) Marshal() []byte {
	return nil
}

//Unmarshal a
func (p ZKre) Unmarshal(b []byte) ZKproof {
	return p
}

//CreateZKre a
func CreateZKre() ZKproof {
	return ZKre{}
}

//ZKexp a
type ZKexp struct {
}

//Verify a
func (p ZKexp) Verify() bool {
	return true
}

//Marshal a
func (p ZKexp) Marshal() []byte {
	return nil
}

//Unmarshal a
func (p ZKexp) Unmarshal(b []byte) ZKproof {
	return p
}

//CreateZKexp a
func CreateZKexp() ZKproof {
	return ZKexp{}
}
