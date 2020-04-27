package sync

// RoundError describes the reason why a round has failed
type RoundError struct {
	msg     string
	missing []uint16
}

func newRoundError(msg string, missing []uint16) error {
	return &RoundError{msg, missing}
}

func (re *RoundError) Error() string {
	return re.msg
}
