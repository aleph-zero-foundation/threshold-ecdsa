package sync

// RoundError describes the reason why a round has failed
type RoundError struct {
	msg     string
	missing []uint16
}

func newRoundError(msg string, missing []uint16) *RoundError {
	return &RoundError{msg, missing}
}

func (re *RoundError) Error() string {
	return re.msg
}

// Missing is a collection of parties that did not send a correct proof
func (re *RoundError) Missing() []uint16 {
	return re.missing
}

func wrap(err error) *RoundError {
	return newRoundError(err.Error(), nil)
}
