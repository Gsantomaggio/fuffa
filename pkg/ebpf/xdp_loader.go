package ebpf

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
	coll, err := ebpf.LoadCollection(x.fileObj)
	if err != nil {
		slog.Error("Error loading eBPF object file", "file", x.fileObj, "error", err)
		return err
	}
	x.collection = coll
	slog.Info("eBPF object file loaded. ", "file", x.fileObj)
	return nil
}
