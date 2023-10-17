package update

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/redhat-et/transmission/pkg/config"
	"github.com/redhat-et/transmission/pkg/daemon"
	"github.com/redhat-et/transmission/pkg/provider/git"
	"k8s.io/klog/v2"
)

var (
	fetchConfigTimeout = 10 * time.Minute
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
	if len(url) == 0 {
		return fmt.Errorf("transmission URL not configured, exiting")
	}

	configDir := filepath.Join("/etc", "transmission")
	stagingDir := filepath.Join("/etc", "transmission", "staging")
	rootDir := filepath.Join("/")
	mock := false
	if os.Geteuid() != 0 {
		userHome := os.Getenv("HOME")
		configDir = filepath.Join(userHome, ".transmission")
		stagingDir = filepath.Join(userHome, ".transmission", "staging")
		rootDir = filepath.Join(userHome, ".transmission", "fakeroot")
		mock = true
	}
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return err
	}

	mcd, err := daemon.New(nil, configDir, rootDir, mock)
	if err != nil {
		return err
	}

	klog.Infof("checking %s for configuration update", url)
	ctx, cancel := context.WithTimeout(context.Background(), fetchConfigTimeout)
	defer cancel()

	cfgProvider := git.New(stagingDir, url, "main", "/")
	hasUpdates, err := cfgProvider.FetchConfig(ctx, mcd.DesiredConfigSet())
	if err != nil {
		return err
	}
	if !hasUpdates {
		klog.Infoln("no updates, exiting")
		return nil
	}

	klog.Infoln("applying update")
	err = mcd.UpdateConfig(mcd.CurrentConfigSet(), mcd.DesiredConfigSet(), false)
	if err != nil {
		return err
	}
	return nil
}
