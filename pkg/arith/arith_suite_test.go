package arith_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"testing"
)

func TestArith(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Arith Suite")
}
