package banner

import (
	"fmt"
	"os"

	"github.com/redhat-et/transmission/pkg/config"
)

type command struct{}

func NewCommand() *command {
	return &command{}
}

func (c *command) Run() error {
	url, err := config.GetTransmissionURL()
	if err != nil {
		return err
	}

	action := "No Transmission URL configured"
	if url != nil {
		action = fmt.Sprintf("Using %s to configure this device\n\n", url.String())
	}
	return os.WriteFile("/run/transmission-banner", []byte(action), 0644)
}
