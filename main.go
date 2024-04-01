package main

import (
	"github.com/cilium/ebpf/link"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"rei/pkg/ebpf"
)

const XdpTcpObj = "./objs/xdp_tcp.o"

func main() {
	slogOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, slogOpts))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	loader, err := ebpf.NewXDPLoader(XdpTcpObj, log)
	if err != nil {
		log.Error("failed to load XDP program: %v", err)
	}

	ifce, err := net.InterfaceByName("ens160")
	if err != nil {
		log.Error("failed to get interface: %v", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   loader.GetCollection().Programs["xdp_tcp_filter"],
		Interface: ifce.Index,
	})
	if err != nil {
		log.Error("error", "failed to attach XDP program", "err", err)
	}
	defer l.Close()

	<-sig
}
