package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log/slog"
	"net"

	xdp_ebpf "rei/pkg/xdp-ebpf"
)

const (
	defaultObjPath  = "./kernel_ebpf/xdp_tcp.o"
	defaultIface    = "ens160"
	programName     = "xdp_tcp_filter"
)

func main() {
	iface := flag.String("iface", defaultIface, "network interface to attach XDP to")
	objPath := flag.String("obj", defaultObjPath, "path to XDP eBPF object file")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	loader, err := xdp_ebpf.NewXDPLoader(*objPath, &ebpf.MapSpec{
		Name:       "port_filter",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}, log)
	if err != nil {
		log.Error("failed to load XDP program", "obj", *objPath, "err", err)
		os.Exit(1)
	}

	ifce, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Error("failed to get interface", "iface", *iface, "err", err)
		os.Exit(1)
	}

	prog, ok := loader.GetCollection().Programs[programName]
	if !ok {
		log.Error("XDP program not found in collection", "name", programName)
		os.Exit(1)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifce.Index,
	})
	if err != nil {
		log.Error("failed to attach XDP program", "iface", *iface, "err", err)
		os.Exit(1)
	}
	defer l.Close()

	log.Info("XDP program attached", "iface", *iface, "obj", *objPath)

	<-sig
	log.Info("shutting down", "reason", "signal received")
}
