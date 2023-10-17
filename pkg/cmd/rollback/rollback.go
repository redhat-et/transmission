package rollback

import (
	"os"
	"path/filepath"

	"github.com/redhat-et/transmission/pkg/daemon"
	"k8s.io/klog/v2"
)

type command struct{}

func NewCommand() *command {
	return &command{}
}

func (c *command) Run() error {
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

	klog.Infoln("rolling back update")
	err = mcd.UpdateConfig(mcd.PreviousConfigSetPath(), mcd.CurrentConfigSet(), false)
	if err != nil {
		return err
	}
	return nil
}
