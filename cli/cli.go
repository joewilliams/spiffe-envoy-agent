package cli

import (
	"log"

	"github.com/mitchellh/cli"
)

func Run(args []string) int {
	c := cli.NewCLI("spiffe-envoy-agent", "0.0.1")
	c.Args = args
	c.Commands = map[string]cli.CommandFactory{
		"run":  newRunCommand,
		"dump": newDumpCommand,
	}

	exitStatus, err := c.Run()
	if err != nil {
		log.Println(err)
	}
	return exitStatus
}
