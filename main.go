package main

import (
	"os"

	"github.com/spiffe/spiffe-envoy-agent/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
