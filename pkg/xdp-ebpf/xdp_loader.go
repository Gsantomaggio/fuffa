package xdp_ebpf

import (
	"github.com/cilium/ebpf"
	"log/slog"
)

type XDPLoader struct {
	fileObj    string           // fileObj is the path to the eBPF object file
	collection *ebpf.Collection // collection is the eBPF collection\
	logger     *slog.Logger
}

// NewXDPLoader creates a new XDPLoader
func NewXDPLoader(fileObj string, logger *slog.Logger) (*XDPLoader, error) {
	xdp := &XDPLoader{
		fileObj: fileObj,
		logger:  logger,
	}

	if err := xdp.load(); err != nil {
		return nil, err
	}

	return xdp, nil

}

// GetCollection returns the eBPF collection
func (x *XDPLoader) GetCollection() *ebpf.Collection {
	return x.collection
}

//func (x *XDPLoader) CollectionToString() string {
//	var str string
//	if x.collection != nil && x.collection.Programs != nil {
//		for _, prog := range x.collection.Programs {
//			str += prog.String() + "\n"
//		}
//	}
//
//	if x.collection != nil && x.collection.Maps != nil {
//		for _, m := range x.collection.Maps {
//			str += m.String() + "\n"
//		}
//	}
//	return str
//}

func (x *XDPLoader) load() error {
	spec, err := ebpf.LoadCollectionSpec(x.fileObj)
	if err != nil {
		slog.Error("Error loading eBPF object file", "file", x.fileObj, "error", err)
		return err
	}

	coll, err := ebpf.NewCollection(spec)
	//if err != nil {
	//	panic(err)
	//}
	//// Close the Collection before the enclosing function returns.
	////defer coll.Close()
	//
	//// Obtain a reference to 'my_map'.
	//m := coll.Maps["port_filter"]
	//
	//var value uint64
	//if err := m.Lookup(uint32(0), &value); err != nil {
	//	log.Fatalf("failed to lookup map: %v", err)
	//}
	//
	//if err := m.Put(uint32(0), uint64(5552)); err != nil {
	//	panic(err)
	//}
	//
	//log.Printf("value: %d\n", value)
	////if err := m.Update(uint32(0), uint64(5552), ebpf.UpdateAny); err != nil {
	//	log.Fatalf("failed to update map: %v", err)
	//}
	x.collection = coll
	slog.Info("eBPF object file loaded. ", "file", x.fileObj)
	return nil
}
