package pkg

// Elem is an element in a group
type Elem struct{}

// DKey is a distirbuted key
type DKey interface {
	Label() string
	RevealExp() (Elem, error)
}

// ADKey is an arithmetic distirbuted key
type ADKey interface {
	DKey
	Reshare(uint16) (TDKey, error)
}

// TDKey is a thresholded distirbuted key
type TDKey interface {
	DKey
	Threshold() uint16
}
