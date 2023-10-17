package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"

	ign3types "github.com/coreos/ignition/v2/config/v3_4/types"
	"k8s.io/klog/v2"
)

// Unlike MCD, Transmission allows for multiple, arbitrarily users to be created
// and have SSH keys added, so we modify MCD's methods accordingly.

func (dn *Daemon) userSSHDirPath(username string) string {
	return filepath.Join(dn.rootDir, "home", username, ".ssh")
}

func (dn *Daemon) userSSHKeyDirPath(username string) string {
	return filepath.Join(dn.rootDir, "home", username, ".ssh", "authorized_keys.d")
}

func userExists(username string) bool {
	_, err := user.Lookup(username)
	return err == nil
}

func createUser(username string) error {
	klog.Infof("Creating user %q", username)
	if out, err := exec.Command("useradd", "--create-home", username).CombinedOutput(); err != nil {
		return fmt.Errorf("Failed to create user %s: %s:%w", username, out, err)
	}
	return nil
}

func (dn *Daemon) createUsers(newUsers []ign3types.PasswdUser) error {
	if len(newUsers) == 0 {
		return nil
	}

	for _, u := range newUsers {
		if !userExists(u.Name) {
			if err := createUser(u.Name); err != nil {
				return err
			}
		}
	}

	return nil
}

// Ensures that both the SSH root directory (/home/$username/.ssh) as well as any
// subdirectories are created with the correct (0700) permissions.
func (dn *Daemon) createSSHKeyDir(username, authKeyDir string) error {
	klog.Infof("Creating missing SSH key dir at %s", authKeyDir)

	mkdir := func(dir string) error {
		return exec.Command("runuser", "-u", username, "--", "mkdir", "-m", "0700", "-p", dir).Run()
	}

	if err := mkdir(dn.userSSHDirPath(username)); err != nil {
		return err
	}
	return mkdir(authKeyDir)
}

func (dn *Daemon) atomicallyWriteSSHKey(username, keys string) error {
	u, err := user.Lookup(username)
	if err != nil {
		return err
	}

	var uid, gid int
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return err
	}
	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return err
	}
	authKeyPath := filepath.Join(dn.rootDir, u.HomeDir, ".ssh", "authorized_keys")

	klog.Infof("Writing SSH keys to %q", authKeyPath)

	authKeyDir := filepath.Dir(authKeyPath)
	if _, err := os.Stat(authKeyDir); os.IsNotExist(err) {
		if err := dn.createSSHKeyDir(u.Name, authKeyDir); err != nil {
			return err
		}
	}

	if err := writeFileAtomically(authKeyPath, []byte(keys), os.FileMode(0o700), os.FileMode(0o600), uid, gid); err != nil {
		return err
	}

	klog.V(2).Infof("Wrote SSH keys to %q", authKeyPath)

	return nil
}

func (dn *Daemon) updateSSHKeys(newUsers []ign3types.PasswdUser) error {
	if len(newUsers) == 0 {
		return nil
	}

	for _, u := range newUsers {
		if !userExists(u.Name) {
			return fmt.Errorf("Failed to add SSH key to non-existing user %s", u.Name)
		}

		var concatSSHKeys string
		for _, k := range u.SSHAuthorizedKeys {
			concatSSHKeys = concatSSHKeys + string(k) + "\n"
		}

		if !dn.mock {
			return dn.atomicallyWriteSSHKey(u.Name, concatSSHKeys)
		}
	}

	return nil
}
