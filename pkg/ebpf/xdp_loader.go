package ebpf

import (
	"github.com/cilium/ebpf"
	"github.com/go-logr/logr"
)

type XDPLoader struct {
	fileObj    string           // fileObj is the path to the eBPF object file
	collection *ebpf.Collection // collection is the eBPF collection\
	logger     logr.Logger
}

// NewXDPLoader creates a new XDPLoader
func NewXDPLoader(fileObj string, logger logr.Logger) *XDPLoader {
	return &XDPLoader{
		fileObj: fileObj,
		logger:  logger,
	}
}

// GetCollection returns the eBPF collection
func (x *XDPLoader) GetCollection() *ebpf.Collection {
	return x.collection
}

func (x *XDPLoader) CollectionToString() string {
	var str string
	for _, prog := range x.collection.Programs {
		str += prog.String() + "\n"
	}
	for _, m := range x.collection.Maps {
		str += m.String() + "\n"
	}
	return str
}

// Load loads the eBPF object file
func (x *XDPLoader) Load() error {
	coll, err := ebpf.LoadCollection(x.fileObj)
	if err != nil {
		x.logger.V(LogNormal).Error(err, "loading eBPF object file", "file", x.fileObj)
		return err
	}
	x.logger.V(LogDebug).Info("eBPF object file loaded", "file", x.fileObj, "collection", x.CollectionToString())
	x.collection = coll
	return nil
}
