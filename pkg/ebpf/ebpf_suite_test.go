package ebpf

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"testing"
)

func TestStream(t *testing.T) {
	defer GinkgoRecover()
	RegisterFailHandler(Fail)
	RunSpecs(t, "fuffa ebpf")
}
