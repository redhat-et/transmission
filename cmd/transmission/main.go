package main

import (
	"fmt"
	"io"
	"os"

	"github.com/redhat-et/transmission/pkg/cmd/banner"
	"github.com/redhat-et/transmission/pkg/cmd/rollback"
	"github.com/redhat-et/transmission/pkg/cmd/update"
	"k8s.io/klog/v2"
)

type Runner interface {
	Run() error
}

var (
	commands = map[string]Runner{
		"rollback":      rollback.NewCommand(),
		"update":        update.NewCommand(),
		"update-banner": banner.NewCommand(),
	}
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr, fmt.Errorf("no command specified"))
	}
	cmd, ok := commands[os.Args[1]]
	if !ok {
		usage(os.Stderr, fmt.Errorf("unknown command %s", os.Args[1]))
	}

	klog.Info("Starting transmission")
	defer klog.Info("Stopping transmission")

	if err := cmd.Run(); err != nil {
		klog.Error(err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func usage(out io.Writer, err error) {
	if err != nil {
		fmt.Fprintf(out, "error: %v\n\n", err)
	}

	fmt.Fprintln(out, `Transmission is a device management agent for ostree-based Linux operating systems.

Usage:
	transmission [command]

Available Commands:
	rollback      roll back to previous configuration set
	update        fetch and apply configuration set
	update-banner update the login banner to display the configuration URL`)
	os.Exit(1)
}
