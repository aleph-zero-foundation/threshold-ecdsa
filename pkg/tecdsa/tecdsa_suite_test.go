package tecdsa_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"testing"
)

func TestTECDSA(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "TECDSA Suite")
}
