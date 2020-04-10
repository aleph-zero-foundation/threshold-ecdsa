package pkg

import (
	"gitlab.com/alephledger/core-go/pkg/network"
	"math/big"
)

// DSecret is a distributed secret
type DSecret interface {
	Label() string
	Reveal() (*big.Int, error)
	Exp() (DKey, error)
}

// ADSecret is an arithmetic distirbuted secret
type ADSecret interface {
	DSecret
	Reshare(uint16) (TDSecret, error)
}

// TDSecret is a thresholded distributed secret
type TDSecret interface {
	DSecret
	Threshold() uint16
}

// Gen generates a new distributed key with given label
func Gen(label string, network network.Server, commType string) ADSecret {
	return nil
}
