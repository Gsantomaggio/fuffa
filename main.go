package main

import (
	"log/slog"
	"os"
	"rei/pkg/ebpf"
)

const XdpTcpObj = "./objs/xdp_tcp.o"

func main() {
	slogOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, slogOpts))

	_, err := ebpf.NewXDPLoader(XdpTcpObj, log)
	if err != nil {
		log.Error("failed to load XDP program: %v", err)
	}
	// Initialize the app with the appropriate configuration
}
