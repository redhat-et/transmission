package daemon

import (
	"os"
	"path/filepath"

	"github.com/openshift/machine-config-operator/pkg/daemon/osrelease"
	"github.com/redhat-et/transmission/pkg/ignition"
	"github.com/redhat-et/transmission/pkg/util"
)

type Daemon struct {
	// os the operating system the MCD is running on
	os osrelease.OperatingSystem
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

	// stagingDirPath is where Transmission stages its configsets
	stagingDirPath = filepath.Join(transmissionDirPath, "staging")

	// pathSystemd is the path systemd modifiable units, services, etc.. reside
	pathSystemd = filepath.Join("etc", "systemd", "system")
	// pathDevNull is the systems path to and endless blackhole
	pathDevNull = "/dev/null"

	// used for certificate syncing
	caBundleFilePath = filepath.Join("etc", "kubernetes", "kubelet-ca.crt")
)

func New(exitCh chan<- error) (*Daemon, error) {
	return &Daemon{}, nil
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

func (dn *Daemon) GetStagingDirPath() string {
	return filepath.Join(rootDirPath, stagingDirPath)
}

// type unreconcilableErr struct {
// 	error
// }
