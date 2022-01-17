package cli

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/colinnewell/pcap-cli/tcp"
	jsoniter "github.com/json-iterator/go"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/spf13/pflag"
)

func Main(usage string, r tcp.ConnectionReader, outputFunc func(chan interface{})) {
	var assemblyDebug, displayVersion bool
	var serverPorts []int32

	pflag.BoolVar(&displayVersion, "version", false, "Display program version")
	pflag.BoolVar(&assemblyDebug, "assembly-debug", false, "Debug log from the tcp assembly")
	pflag.Int32SliceVar(&serverPorts, "server-ports", []int32{}, "Server ports")
	pflag.Parse()

	if displayVersion {
		fmt.Printf("Version: %s\n", Version)
		return
	}

	if assemblyDebug {
		// set the flag the pcap library reads to
		// know it needs to output debug info.
		if err := flag.Set("assembly_debug_log", "true"); err != nil {
			log.Fatal(err)
		}
	}

	files := pflag.Args()

	if len(files) == 0 {
		log.Fatal("Must specify filename")
	}

	streamFactory := tcp.NewFactory(r)
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	for _, filename := range files {
		if handle, err := pcap.OpenOffline(filename); err != nil {
			log.Fatal(err)
		} else {
			defer handle.Close()
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

			for packet := range packetSource.Packets() {
				if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
					if allowPort(serverPorts, tcp) {
						assembler.AssembleWithTimestamp(
							packet.NetworkLayer().NetworkFlow(),
							tcp, packet.Metadata().Timestamp)
					}
				}
			}
		}
	}

	assembler.FlushAll()

	streamFactory.Output(outputFunc)
}

func allowPort(serverPorts []int32, packet *layers.TCP) bool {
	if len(serverPorts) == 0 {
		return true
	}

	for _, port := range serverPorts {
		if packet.SrcPort == layers.TCPPort(port) ||
			packet.DstPort == layers.TCPPort(port) {
			return true
		}
	}

	return false
}

func SimpleJSONOutput(o *os.File) func(chan interface{}) {
	return func(completed chan interface{}) {
		var json = jsoniter.ConfigCompatibleWithStandardLibrary
		e := json.NewEncoder(os.Stdout)
		e.SetIndent("  ", "  ")

		fmt.Fprint(o, "[\n  ")
		first := true
		for c := range completed {
			if first {
				first = false
			} else {
				// this sucks.
				fmt.Fprintf(o, "  ,\n  ")
			}
			err := e.Encode(c)
			if err != nil {
				log.Println(o, err)
				return
			}
		}
		fmt.Fprintln(o, "]")
	}
}
