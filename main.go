package main

import (
	"bufio"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"rei/pkg/xdp-ebpf"
)

const XdpTcpObj = "./kernel_ebpf/xdp_tcp.o"

func main() {
	slogOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, slogOpts))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("failed to remove memlock: %v", err)
	}
	loader, err := xdp_ebpf.NewXDPLoader(XdpTcpObj, log)
	if err != nil {
		log.Error("failed to load XDP program: %v", err)
		return
	}

	ifce, err := net.InterfaceByName("ens160")
	if err != nil {
		log.Error("failed to get interface: %v", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   loader.GetCollection().Programs["xdp_tcp_redirect"],
		Interface: ifce.Index,
	})
	if err != nil {
		log.Error("error", "failed to attach XDP program", "err", err)
	}

	var value2 uint64
	value2 = 5553

	if err := loader.GetCollection().Maps["port_filter"].Put(uint32(0), &value2); err != nil {
		slog.Error("failed to lookup map: %v", err)
	}

	//ln, err := net.Listen("tcp", ":5553")
	//if err != nil {
	//	log.Error("failed to open TCP port: %v", err)
	//}
	//
	//go func() {
	//	for {
	//		conn, err := ln.Accept()
	//		if err != nil {
	//			fmt.Printf("failed to accept connection: %v", err)
	//			continue
	//		}
	//		// Handle the connection
	//		//fmt.Printf("Connection accepted")
	//		go handleConnection(conn)
	//	}
	//}()
	//
	//defer ln.Close()

	//fmt.Println("TCP load balancer listening on port 5553...")

	//time.Sleep(2 * time.Second)
	//var value uint64
	//if err := loader.GetCollection().Maps["port_filter"].Lookup(uint32(0), &value); err != nil {
	//	slog.Error("failed to lookup map: %v", err)
	//}
	//
	//slog.Info("port_filter[0] ", value)
	//time.Sleep(2 * time.Second)
	//
	//var value2 uint64
	//value2 = 1234
	//
	//if err := loader.GetCollection().Maps["port_filter"].Put(uint32(0), &value2); err != nil {
	//	slog.Error("failed to lookup map: %v", err)
	//}
	//
	//if err := loader.GetCollection().Maps["port_filter"].Lookup(uint32(0), &value); err != nil {
	//
	//	slog.Error("failed to lookup map: %v", err)
	//}

	//log.Info("port_filter[0]: %d", value)

	defer l.Close()

	<-sig
}

func handleConnection(conn net.Conn) {

	reader := bufio.NewReader(conn)
	for {
		message, err := reader.ReadByte()
		if err != nil {
			log.Printf("failed to read from connection: %v", err)
			return
		}
		log.Printf("Received message: %s", message)
		_, err = conn.Write([]byte{message})
	}

}
