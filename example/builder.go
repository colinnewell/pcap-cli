package example

import (
	"bytes"
	"io"
	"sync"

	"github.com/colinnewell/pcap-cli/general"
	"github.com/colinnewell/pcap-cli/tcp"
)

type ExampleConnection struct {
	Address      string
	ClientStream []byte
	ServerStream []byte
}

type ExampleConnectionBuilder struct {
	address       tcp.ConnectionAddress
	completed     chan interface{}
	sidesComplete uint8
	mu            sync.Mutex
	clientData    bytes.Buffer
	serverData    bytes.Buffer
}

func (b *ExampleConnectionBuilder) ReadClientStream(s *tcp.TimeCaptureReader) error {
	_, err := io.Copy(&b.clientData, s)
	return err
}

func (b *ExampleConnectionBuilder) ReadServerStream(s *tcp.TimeCaptureReader) error {
	_, err := io.Copy(&b.serverData, s)
	return err
}

func (b *ExampleConnectionBuilder) ReadDone() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sidesComplete++
	if b.sidesComplete == 2 {
		b.completed <- &ExampleConnection{
			Address:      b.address.String(),
			ClientStream: b.clientData.Bytes(),
			ServerStream: b.serverData.Bytes(),
		}
	}
}

type ExampleConnectionBuilderFactory struct{}

func (f *ExampleConnectionBuilderFactory) NewBuilder(address tcp.ConnectionAddress, completed chan interface{}) general.ConnectionBuilder {
	return &ExampleConnectionBuilder{address: address, completed: completed}
}
