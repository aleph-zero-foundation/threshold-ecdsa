package crypto

import (
	"math/big"

	"github.com/binance-chain/tss-lib/crypto/paillier"
)

const modulusBitLen = 256
const timeout = 10000

//PaillierPrivateKey wrapper for Private Key in Paillier encryption
type PaillierPrivateKey struct {
	key *paillier.PrivateKey
}

//PaillierPublicKey wrapper for Public Key in Paillier encryption
type PaillierPublicKey struct {
	key *paillier.PublicKey
}

//Marshal Marshall Paillier Public Key
func (p PaillierPublicKey) Marshal() []byte {
	return p.key.N.Bytes()
}

//Unmarshal Unmarshall Paillier Public Key
func (p PaillierPublicKey) Unmarshal(b []byte) PaillierPublicKey {
	p.key.N.SetBytes(b)
	return p
}

//Encrypt Encrypt given value base on this Paillier Public Key
func (p PaillierPublicKey) Encrypt(value *big.Int) (*big.Int, error) {
	return p.key.Encrypt(value)
}

//Decode Decrypt given value with this Paillier Private Key
func (p PaillierPrivateKey) Decrypt(value *big.Int) (*big.Int, error) {
	return p.key.Decrypt(value)
}

//Add Add two values which are under encryption based on this Paillier Public Key
func (p PaillierPublicKey) Add(a, b *big.Int) (*big.Int, error) {
	return p.key.HomoAdd(a, b)
}

//Mult Mult two values which are under encryption based on this Paillier Public Key
func (p PaillierPublicKey) Mult(a, b *big.Int) (*big.Int, error) {
	return p.key.HomoMult(a, b)
}

//CreateKeys Create pair of keys for Paillier Encryption
func CreateKeys() (PaillierPrivateKey, PaillierPublicKey) {
	sk, pk, _ := paillier.GenerateKeyPair(modulusBitLen, timeout)
	return PaillierPrivateKey{sk}, PaillierPublicKey{pk}
}
