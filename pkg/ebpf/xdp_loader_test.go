package ebpf

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"os"
)

const XdpTcpObj = "../../objs/xdp_tcp.o"

// XDPLoader is a struct that contains the eBPF object file path, the eBPF collection and a logger

var _ = Describe("XDPLoader", func() {

	Context("NewXDPLoader", func() {

		It("should load the xdp_tcp object  ", func() {
			fileInfo, err := os.Stat(XdpTcpObj)
			Expect(err).To(BeNil())
			Expect(fileInfo.Size()).To(BeNumerically(">", 0))
			loader := NewXDPLoader(XdpTcpObj, GinkgoLogr)
			Expect(loader).NotTo(BeNil())
			Expect(loader.logger).To(Equal(GinkgoLogr))
			Expect(loader.fileObj).To(Equal(XdpTcpObj))
			Expect(loader.Load()).To(BeNil())
		})
	})
})
