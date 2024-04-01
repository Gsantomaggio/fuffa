package ebpf

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"os"
)

const XdpTcpObj = "../../objs/xdp_tcp.o"

// XDPLoader is a struct that contains the eBPF object file path, the eBPF collection and a loggerTestSuite

var _ = Describe("XDPLoader", func() {

	Context("NewXDPLoader", func() {
		It("should load the xdp_tcp object  ", func() {
			fileInfo, err := os.Stat(XdpTcpObj)
			Expect(err).To(BeNil())
			Expect(fileInfo.Size()).To(BeNumerically(">", 0))
			loader, err := NewXDPLoader(XdpTcpObj, loggerTestSuite)
			Expect(err).To(BeNil())
			Expect(loader).NotTo(BeNil())
			Expect(loader.fileObj).To(Equal(XdpTcpObj))
			Expect(loader.GetCollection()).NotTo(BeNil())
			Expect(loader.GetCollection().Programs["xdp_tcp_filter"]).NotTo(BeNil())
		})
	})
})
