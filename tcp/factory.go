package tcp

import (
	"fmt"
	"log"
	"os"
	"sync"

	gpkt "github.com/colinnewell/pcap-cli/internal/gopacket"
	jsoniter "github.com/json-iterator/go"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type ConnectionReader interface {
	ReadStream(r Stream, a, b gopacket.Flow)
}

type StreamFactory struct {
	reader    ConnectionReader
	wg        sync.WaitGroup
	completed chan interface{}
}

func NewFactory(r ConnectionReader) *StreamFactory {
	return &StreamFactory{
		reader:    r,
		completed: make(chan interface{}),
	}
}

func (f *StreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	r := gpkt.NewReaderStream()
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		f.reader.ReadStream(&r, a, b)
	}()
	return &r
}

func (f *StreamFactory) Output(o *os.File) {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("  ", "  ")
	go func() {
		f.wg.Wait()
		close(f.completed)
	}()
	fmt.Print("[\n  ")
	first := true
	for c := range f.completed {
		if first {
			first = false
		} else {
			// this sucks.
			fmt.Printf("  ,\n  ")
		}
		err := e.Encode(c)
		if err != nil {
			log.Println(err)
			return
		}
	}
	fmt.Println("]")
}
