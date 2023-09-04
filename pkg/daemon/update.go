// adapted from https://github.com/openshift/machine-config-operator/blob/master/pkg/daemon/update.go
package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	ign3types "github.com/coreos/ignition/v2/config/v3_4/types"
	"github.com/golang/glog"
	"github.com/redhat-et/transmission/pkg/ignition"
	kubeErrs "k8s.io/apimachinery/pkg/util/errors"
)

const (
	// defaultDirectoryPermissions houses the default mode to use when no directory permissions are provided
	defaultDirectoryPermissions os.FileMode = 0o755
	// defaultFilePermissions houses the default mode to use when no file permissions are provided
	defaultFilePermissions os.FileMode = 0o644
)

func (dn *Daemon) UpdateConfig(oldConfigName string, newConfigName string, skipCertificateWrite bool) (retErr error) {
	oldIgnConfig, err := ignition.Load(oldConfigName)
	if err != nil {
		return fmt.Errorf("loading old Ignition config failed: %w", err)
	}
	newIgnConfig, err := ignition.Load(newConfigName)
	if err != nil {
		return fmt.Errorf("loading new Ignition config failed: %w", err)
	}

	// glog.Infof("Checking Reconcilable for config %v to %v", oldConfigName, newConfigName)

	// // make sure we can actually reconcile this state
	// diff, reconcilableError := reconcilable(oldConfig, newConfig)
	// if reconcilableError != nil {
	// 	wrappedErr := fmt.Errorf("can't reconcile config %s with %s: %w", oldConfigName, newConfigName, reconcilableError)
	// 	return &unreconcilableErr{wrappedErr}
	// }

	// glog.Infof("Starting update from %s to %s: %+v", oldConfigName, newConfigName, diff)

	// update files on disk that need updating
	if err := dn.updateFiles(oldIgnConfig, newIgnConfig, skipCertificateWrite); err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			if err := dn.updateFiles(newIgnConfig, oldIgnConfig, skipCertificateWrite); err != nil {
				errs := kubeErrs.NewAggregate([]error{err, retErr})
				retErr = fmt.Errorf("error rolling back files writes: %w", errs)
				return
			}
		}
	}()

	if err := dn.createUsers(newIgnConfig.Passwd.Users); err != nil {
		return err
	}

	if err := dn.updateSSHKeys(newIgnConfig.Passwd.Users); err != nil {
		return err
	}

	defer func() {
		if retErr != nil {
			if err := dn.updateSSHKeys(oldIgnConfig.Passwd.Users); err != nil {
				errs := kubeErrs.NewAggregate([]error{err, retErr})
				retErr = fmt.Errorf("error rolling back SSH keys updates: %w", errs)
				return
			}
		}
	}()

	// Set password hash
	if err := dn.SetPasswordHash(newIgnConfig.Passwd.Users); err != nil {
		return err
	}

	defer func() {
		if retErr != nil {
			if err := dn.SetPasswordHash(oldIgnConfig.Passwd.Users); err != nil {
				errs := kubeErrs.NewAggregate([]error{err, retErr})
				retErr = fmt.Errorf("error rolling back password hash updates: %w", errs)
				return
			}
		}
	}()

	// if dn.os.IsCoreOSVariant() {
	// 	coreOSDaemon := CoreOSDaemon{dn}
	// 	if err := coreOSDaemon.applyOSChanges(*diff, oldConfig, newConfig); err != nil {
	// 		return err
	// 	}

	// 	defer func() {
	// 		if retErr != nil {
	// 			if err := coreOSDaemon.applyOSChanges(*diff, newConfig, oldConfig); err != nil {
	// 				errs := kubeErrs.NewAggregate([]error{err, retErr})
	// 				retErr = fmt.Errorf("error rolling back changes to OS: %w", errs)
	// 				return
	// 			}
	// 		}
	// 	}()
	// } else {
	// 	glog.Info("updating the OS on non-CoreOS nodes is not supported")
	// }

	// // Ideally we would want to update kernelArguments only via MachineConfigs.
	// // We are keeping this to maintain compatibility and OKD requirement.
	// if err := UpdateTuningArgs(KernelTuningFile, CmdLineFile); err != nil {
	// 	return err
	// }

	// At this point, we write the now expected to be "current" config to /etc.
	// When we reboot, we'll find this file and validate that we're in this state,
	// and that completes an update.
	if err := dn.storeCurrentConfigOnDisk(&newIgnConfig); err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			if err := dn.storeCurrentConfigOnDisk(&oldIgnConfig); err != nil {
				errs := kubeErrs.NewAggregate([]error{err, retErr})
				retErr = fmt.Errorf("error rolling back current config on disk: %w", errs)
				return
			}
		}
	}()

	// if err := dn.finalizeBeforeReboot(newConfig); err != nil {
	// 	return err
	// }

	// return dn.performPostConfigChangeAction(actions, newConfig.GetName())
	return nil
}

// updateFiles writes files specified by the nodeconfig to disk. it also writes
// systemd units. there is no support for multiple filesystems at this point.
//
// in addition to files, we also write systemd units to disk. we mask, enable,
// and disable unit files when appropriate. this function relies on the system
// being restarted after an upgrade, so it doesn't daemon-reload or restart
// any services.
//
// it is worth noting that this function explicitly doesn't rely on the ignition
// implementation of file, unit writing, enabling or disabling. this is because
// ignition is built on the assumption that it is working with a fresh system,
// where as we are trying to reconcile a system that has already been running.
//
// in the future, this function should do any additional work to confirm that
// whatever has been written is picked up by the appropriate daemons, if
// required. in particular, a daemon-reload and restart for any unit files
// touched.
func (dn *Daemon) updateFiles(oldIgnConfig, newIgnConfig ign3types.Config, skipCertificateWrite bool) error {
	glog.Info("Updating files")
	if err := dn.writeFiles(newIgnConfig.Storage.Files, skipCertificateWrite); err != nil {
		return err
	}
	if err := dn.writeUnits(newIgnConfig.Systemd.Units); err != nil {
		return err
	}
	if err := dn.deleteStaleData(oldIgnConfig, newIgnConfig); err != nil {
		return err
	}
	return nil
}

func restorePath(path string) error {
	if out, err := exec.Command("cp", "-a", "--reflink=auto", origFileName(path), path).CombinedOutput(); err != nil {
		return fmt.Errorf("restoring %q from orig file %q: %s: %w", path, origFileName(path), string(out), err)
	}
	if err := os.Remove(origFileName(path)); err != nil {
		return fmt.Errorf("deleting orig file %q: %w", origFileName(path), err)
	}
	return nil
}

// parse path to find out if its a systemd dropin
// Returns is dropin (true/false), service name, dropin name
func isPathASystemdDropin(path string) (bool, string, string) {
	if !strings.HasPrefix(path, "/etc/systemd/system") {
		return false, "", ""
	}
	if !strings.HasSuffix(path, ".conf") {
		return false, "", ""
	}
	pathSegments := strings.Split(path, "/")
	dropinName := pathSegments[len(pathSegments)-1]
	servicePart := pathSegments[len(pathSegments)-2]
	allServiceSegments := strings.Split(servicePart, ".")
	if allServiceSegments[len(allServiceSegments)-1] != "d" {
		return false, "", ""
	}
	serviceName := strings.Join(allServiceSegments[:len(allServiceSegments)-1], ".")
	return true, serviceName, dropinName
}

// iterate systemd units and return true if this path is already covered by a systemd dropin
func (dn *Daemon) isPathInDropins(path string, systemd *ign3types.Systemd) bool {
	if ok, service, dropin := isPathASystemdDropin(path); ok {
		for _, u := range systemd.Units {
			if u.Name == service {
				for _, j := range u.Dropins {
					if j.Name == dropin {
						return true
					}
				}
			}
		}
	}
	return false
}

// deleteStaleData performs a diff of the new and the old Ignition config. It then deletes
// all the files, units that are present in the old config but not in the new one.
// this function will error out if it fails to delete a file (with the exception
// of simply warning if the error is ENOENT since that's the desired state).
//
//nolint:gocyclo
func (dn *Daemon) deleteStaleData(oldIgnConfig, newIgnConfig ign3types.Config) error {
	glog.Info("Deleting stale data")
	newFileSet := make(map[string]struct{})
	for _, f := range newIgnConfig.Storage.Files {
		newFileSet[f.Path] = struct{}{}
	}

	for _, f := range oldIgnConfig.Storage.Files {
		if _, ok := newFileSet[f.Path]; ok {
			continue
		}
		if _, err := os.Stat(noOrigFileStampName(f.Path)); err == nil {
			if delErr := os.Remove(noOrigFileStampName(f.Path)); delErr != nil {
				return fmt.Errorf("deleting noorig file stamp %q: %w", noOrigFileStampName(f.Path), delErr)
			}
			glog.V(2).Infof("Removing file %q completely", f.Path)
		} else if _, err := os.Stat(origFileName(f.Path)); err == nil {
			// Add a check for backwards compatibility: basically if the file doesn't exist in /usr/etc (on FCOS/RHCOS)
			// and no rpm is claiming it, we assume that the orig file came from a wrongful backup of a MachineConfig
			// file instead of a file originally on disk. See https://bugzilla.redhat.com/show_bug.cgi?id=1814397
			var restore bool
			if _, err := exec.Command("rpm", "-qf", f.Path).CombinedOutput(); err == nil {
				// File is owned by an rpm
				restore = true
			} else if strings.HasPrefix(f.Path, "/etc") && dn.os.IsCoreOSVariant() {
				if _, err := os.Stat(withUsrPath(f.Path)); err != nil {
					if !os.IsNotExist(err) {
						return err
					}

					// If the error is ErrNotExist then we don't restore the file
				} else {
					restore = true
				}
			}

			if restore {
				if err := restorePath(f.Path); err != nil {
					return err
				}
				glog.V(2).Infof("Restored file %q", f.Path)
				continue
			}

			if delErr := os.Remove(origFileName(f.Path)); delErr != nil {
				return fmt.Errorf("deleting orig file %q: %w", origFileName(f.Path), delErr)
			}
		}

		// Check Systemd.Units.Dropins - don't remove the file if configuration has been converted into a dropin
		if dn.isPathInDropins(f.Path, &newIgnConfig.Systemd) {
			glog.Infof("Not removing file %q: replaced with systemd dropin", f.Path)
			continue
		}

		glog.V(2).Infof("Deleting stale config file: %s", f.Path)
		if err := os.Remove(filepath.Join(rootDirPath, f.Path)); err != nil {
			newErr := fmt.Errorf("unable to delete %s: %w", f.Path, err)
			if !os.IsNotExist(err) {
				return newErr
			}
			// otherwise, just warn
			glog.Warningf("%v", newErr)
		}
		glog.Infof("Removed stale file %q", f.Path)
	}

	newUnitSet := make(map[string]struct{})
	newDropinSet := make(map[string]struct{})
	for _, u := range newIgnConfig.Systemd.Units {
		for j := range u.Dropins {
			path := filepath.Join(pathSystemd, u.Name+".d", u.Dropins[j].Name)
			newDropinSet[path] = struct{}{}
		}
		path := filepath.Join(pathSystemd, u.Name)
		newUnitSet[path] = struct{}{}
	}

	for _, u := range oldIgnConfig.Systemd.Units {
		for j := range u.Dropins {
			path := filepath.Join(pathSystemd, u.Name+".d", u.Dropins[j].Name)
			if _, ok := newDropinSet[path]; !ok {
				if _, err := os.Stat(noOrigFileStampName(path)); err == nil {
					if delErr := os.Remove(noOrigFileStampName(path)); delErr != nil {
						return fmt.Errorf("deleting noorig file stamp %q: %w", noOrigFileStampName(path), delErr)
					}
					glog.V(2).Infof("Removing file %q completely", path)
				} else if _, err := os.Stat(origFileName(path)); err == nil {
					if err := restorePath(path); err != nil {
						return err
					}
					glog.V(2).Infof("Restored file %q", path)
					continue
				}
				glog.V(2).Infof("Deleting stale systemd dropin file: %s", path)
				if err := os.Remove(path); err != nil {
					newErr := fmt.Errorf("unable to delete %s: %w", path, err)
					if !os.IsNotExist(err) {
						return newErr
					}
					// otherwise, just warn
					glog.Warningf("%v", newErr)
				}
				glog.Infof("Removed stale systemd dropin %q", path)
			}
		}
		path := filepath.Join(pathSystemd, u.Name)
		if _, ok := newUnitSet[path]; !ok {
			// since the unit doesn't exist anymore within the MachineConfig,
			// look to restore defaults here, so that symlinks are removed first
			// if the system has the service disabled
			// writeUnits() will catch units that still have references in other MCs
			if err := dn.presetUnit(u); err != nil {
				glog.Infof("Did not restore preset for %s (may not exist): %s", u.Name, err)
			}
			if _, err := os.Stat(noOrigFileStampName(path)); err == nil {
				if delErr := os.Remove(noOrigFileStampName(path)); delErr != nil {
					return fmt.Errorf("deleting noorig file stamp %q: %w", noOrigFileStampName(path), delErr)
				}
				glog.V(2).Infof("Removing file %q completely", path)
			} else if _, err := os.Stat(origFileName(path)); err == nil {
				if err := restorePath(path); err != nil {
					return err
				}
				glog.V(2).Infof("Restored file %q", path)
				continue
			}
			glog.V(2).Infof("Deleting stale systemd unit file: %s", path)
			if err := os.Remove(path); err != nil {
				newErr := fmt.Errorf("unable to delete %s: %w", path, err)
				if !os.IsNotExist(err) {
					return newErr
				}
				// otherwise, just warn
				glog.Warningf("%v", newErr)
			}
			glog.Infof("Removed stale systemd unit %q", path)
		}
	}

	return nil
}

// enableUnits enables a set of systemd units via systemctl, if any fail all fails.
func (dn *Daemon) enableUnits(units []string) error {
	args := append([]string{"enable"}, units...)
	stdouterr, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		if !dn.os.IsLikeTraditionalRHEL7() {
			return fmt.Errorf("error enabling units: %s", stdouterr)
		}
		// In RHEL7, the systemd version is too low, so it is unable to handle broken
		// symlinks during enable. Do a best-effort removal of potentially broken
		// hard coded symlinks and try again.
		// See: https://bugzilla.redhat.com/show_bug.cgi?id=1913536
		wantsPathSystemd := "/etc/systemd/system/multi-user.target.wants/"
		for _, unit := range units {
			unitLinkPath := filepath.Join(wantsPathSystemd, unit)
			fi, fiErr := os.Lstat(unitLinkPath)
			if fiErr != nil {
				if !os.IsNotExist(fiErr) {
					return fmt.Errorf("error trying to enable unit, fallback failed with %s (original error %s)",
						fiErr, stdouterr)
				}
				continue
			}
			if fi.Mode()&os.ModeSymlink == 0 {
				return fmt.Errorf("error trying to enable unit, a non-symlink file exists at %s (original error %s)",
					unitLinkPath, stdouterr)
			}
			if _, evalErr := filepath.EvalSymlinks(unitLinkPath); evalErr != nil {
				// this is a broken symlink, remove
				if rmErr := os.Remove(unitLinkPath); rmErr != nil {
					return fmt.Errorf("error trying to enable unit, cannot remove broken symlink: %s (original error %s)",
						rmErr, stdouterr)
				}
			}
		}
		stdouterr, err := exec.Command("systemctl", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("error enabling units: %s", stdouterr)
		}
	}
	glog.Infof("Enabled systemd units: %v", units)
	return nil
}

// disableUnits disables a set of systemd units via systemctl, if any fail all fails.
func (dn *Daemon) disableUnits(units []string) error {
	args := append([]string{"disable"}, units...)
	stdouterr, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error disabling unit: %s", stdouterr)
	}
	glog.Infof("Disabled systemd units %v", units)
	return nil
}

// presetUnit resets a systemd unit to its preset via systemctl
func (dn *Daemon) presetUnit(unit ign3types.Unit) error {
	args := []string{"preset", unit.Name}
	stdouterr, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error running preset on unit: %s", stdouterr)
	}
	glog.Infof("Preset systemd unit %s", unit.Name)
	return nil
}

// writeUnits writes the systemd units to disk
func (dn *Daemon) writeUnits(units []ign3types.Unit) error {
	var enabledUnits []string
	var disabledUnits []string

	isCoreOSVariant := dn.os.IsCoreOSVariant()

	for _, u := range units {
		if err := writeUnit(u, pathSystemd, isCoreOSVariant); err != nil {
			return fmt.Errorf("daemon could not write systemd unit: %w", err)
		}
		// if the unit doesn't note if it should be enabled or disabled then
		// honour system presets. This to account for an edge case where you
		// deleted a MachineConfig that enabled/disabled the unit to revert,
		// but the unit itself is referenced in other MCs. deleteStaleData() will
		// catch fully deleted units.
		// if the unit should be enabled/disabled, then enable/disable it.
		// this is a no-op if the system wasn't change this iteration
		// Also, enable and disable as one command, as if any operation fails
		// we'd bubble up the error anyways, and we save a lot of time doing this.
		// Presets must be done individually as we don't consider a failed preset
		// as an error, but it would cause other presets that would have succeeded
		// to not go through.

		if u.Enabled != nil {
			if *u.Enabled {
				enabledUnits = append(enabledUnits, u.Name)
			} else {
				disabledUnits = append(disabledUnits, u.Name)
			}
		} else {
			if err := dn.presetUnit(u); err != nil {
				// Don't fail here, since a unit may have a dropin referencing a nonexisting actual unit
				glog.Infof("Could not reset unit preset for %s, skipping. (Error msg: %v)", u.Name, err)
			}
		}
	}

	if len(enabledUnits) > 0 {
		if err := dn.enableUnits(enabledUnits); err != nil {
			return err
		}
	}
	if len(disabledUnits) > 0 {
		if err := dn.disableUnits(disabledUnits); err != nil {
			return err
		}
	}
	return nil
}

// writeFiles writes the given files to disk.
// it doesn't fetch remote files and expects a flattened config file.
func (dn *Daemon) writeFiles(files []ign3types.File, skipCertificateWrite bool) error {
	return writeFiles(files, skipCertificateWrite)
}

// Set a given PasswdUser's Password Hash
func (dn *Daemon) SetPasswordHash(newUsers []ign3types.PasswdUser) error {
	// confirm that user exits
	if len(newUsers) == 0 {
		return nil
	}

	// var uErr user.UnknownUserError
	// switch _, err := user.Lookup(constants.CoreUserName); {
	// case err == nil:
	// case errors.As(err, &uErr):
	// 	glog.Info("core user does not exist, and creating users is not supported, so ignoring configuration specified for core user")
	// 	return nil
	// default:
	// 	return fmt.Errorf("failed to check if user core exists: %w", err)
	// }

	// SetPasswordHash sets the password hash of the specified user.
	for _, u := range newUsers {
		pwhash := "*"
		if u.PasswordHash != nil && *u.PasswordHash != "" {
			pwhash = *u.PasswordHash
		}

		if out, err := exec.Command("usermod", "-p", pwhash, u.Name).CombinedOutput(); err != nil {
			return fmt.Errorf("Failed to change password for %s: %s:%w", u.Name, out, err)
		}
		glog.Info("Password has been configured")
	}

	return nil
}
