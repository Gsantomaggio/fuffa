package ebpf

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"log/slog"
	"testing"
)

var loggerTestSuite *slog.Logger

func TestStream(t *testing.T) {
	defer GinkgoRecover()
	RegisterFailHandler(Fail)
	RunSpecs(t, "fuffa ebpf")
}

var _ = BeforeSuite(func() {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	loggerTestSuite = slog.New(slog.NewTextHandler(GinkgoWriter, opts))
})
