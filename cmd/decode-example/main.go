package main

import (
	"github.com/colinnewell/pcap-cli/cli"
	"github.com/colinnewell/pcap-cli/example"
	"github.com/colinnewell/pcap-cli/general"
	"github.com/spf13/pflag"
)

func main() {
	f := example.ConnectionBuilderFactory{}
	r := general.NewReader(&f)
	pflag.BoolVar(&r.Verbose, "verbose", false, "Verbose about things errors")
	cli.Main("", r, cli.SimpleJSONOutput)
}
