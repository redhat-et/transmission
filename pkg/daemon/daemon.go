package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	ign3types "github.com/coreos/ignition/v2/config/v3_4/types"
	"github.com/golang/glog"
	"github.com/openshift/machine-config-operator/pkg/daemon/osrelease"
	"github.com/redhat-et/transmission/pkg/ignition"
	"github.com/redhat-et/transmission/pkg/util"
)

type Daemon struct {
	// os the operating system the MCD is running on
	os osrelease.OperatingSystem

	// mock is set if we're running as non-root, probably under unit tests
	mock bool

	// bootID is a unique value per boot (generated by the kernel)
	bootID string

	// channel used by callbacks to signal Run() of an error
	exitCh chan<- error

	// channel used to ensure all spawned goroutines exit when we exit.
	stopCh <-chan struct{}
}

var (
	// rootPath is the path to the file system root
	rootDirPath = filepath.Join("/")

	// transmissionDirPath is where Transmission stores its config and state
	transmissionDirPath = filepath.Join("etc", "transmission")

	// configSetDirPath is where Transmission stores its configsets
	configSetDirPath = filepath.Join(transmissionDirPath, "configsets")

	// desiredConfigSetPath is the path to the desired configset
	desiredConfigSetPath = filepath.Join(configSetDirPath, "desired.ign")

	// currentConfigSetPath is the path to the current configset
	currentConfigSetPath = filepath.Join(configSetDirPath, "current.ign")

	// previousConfigSetPath is the path to the backup of current configset when it gets updated
	previousConfigSetPath = filepath.Join(configSetDirPath, "previous.ign")

	// stagingDirPath is where Transmission stages its configsets
	stagingDirPath = filepath.Join(transmissionDirPath, "staging")

	// pathSystemd is the path systemd modifiable units, services, etc.. reside
	pathSystemd = "/etc/systemd/system"
	// pathDevNull is the systems path to and endless blackhole
	pathDevNull = "/dev/null"

	// used for certificate syncing
	caBundleFilePath = "/etc/kubernetes/kubelet-ca.crt"
)

func New(
	exitCh chan<- error,
) (*Daemon, error) {
	mock := false
	if os.Getuid() != 0 {
		mock = true
	}

	var (
		err error
	)

	hostos := osrelease.OperatingSystem{}
	if !mock {
		hostos, err = osrelease.GetHostRunningOS()
		if err != nil {
			return nil, fmt.Errorf("checking operating system: %w", err)
		}
	}

	// bootID := ""
	// if !mock {
	// 	bootID, err = getBootID()
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to read boot ID: %w", err)
	// 	}
	// }

	return &Daemon{
		mock: mock,
		os:   hostos,
		// bootID: bootID,
		exitCh: exitCh,
	}, nil
}

func (dn *Daemon) SetRootDir(path string) {
	rootDirPath = path
}

func (dn *Daemon) InitDirs() {
	util.Must(os.MkdirAll(dn.GetStagingDirPath(), 0755))
	util.Must(os.MkdirAll(dn.GetConfigSetDirPath(), 0755))
	util.Must(ignition.EnsureExists(dn.GetCurrentConfigSetPath()))
}

func (dn *Daemon) GetConfigSetDirPath() string {
	return filepath.Join(rootDirPath, configSetDirPath)
}

func (dn *Daemon) GetDesiredConfigSetPath() string {
	return filepath.Join(rootDirPath, desiredConfigSetPath)
}

func (dn *Daemon) GetCurrentConfigSetPath() string {
	return filepath.Join(rootDirPath, currentConfigSetPath)
}

func (dn *Daemon) GetPreviousConfigSetPath() string {
	return filepath.Join(rootDirPath, previousConfigSetPath)
}

func (dn *Daemon) GetStagingDirPath() string {
	return filepath.Join(rootDirPath, stagingDirPath)
}

// type unreconcilableErr struct {
// 	error
// }

// storeCurrentConfigOnDisk serializes a machine config into a file in /etc,
// which we use to denote that we are expecting the system has transitioned
// into this state.
func (dn *Daemon) storeCurrentConfigOnDisk(current *ign3types.Config) error {
	ign, err := json.Marshal(current)
	if err != nil {
		return err
	}
	if os.Rename(dn.GetCurrentConfigSetPath(), dn.GetPreviousConfigSetPath()) != nil {
		glog.Warningf("Failed to rename %s to %s: %w", dn.GetCurrentConfigSetPath(), dn.GetPreviousConfigSetPath(), err)
	}
	return writeFileAtomicallyWithDefaults(dn.GetCurrentConfigSetPath(), ign)
}