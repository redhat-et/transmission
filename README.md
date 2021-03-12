# Transmission
## About
Transmission is an experimental device management agent for `ostree`-based Linux operating systems.

It manages device configuration similar to `ostree` managing the device OS, i.e. it allows pulling updates to sets of configuration and appling / reverting them transactionally, reloading `systemd` units as necessary. This includes configuration of the target OS version to run, and Transmission will delegate OS updates/rollbacks to `rpm-ostree` or other agents accordingly.

## Usage
### Installation
Transmission comes as `.rpm` file and is meant to be included into the `ostree` image, e.g. by including it into `OSBuilder` blueprints. It will install a `systemd timer` to run periodically every X minutes.

Users need to provide Transmission with the URL of the device management service to query for updates, either by supplying the `transmission.url` kernel argument or by writing this URL to one of the following locations (which it will search in order): `/usr/lib/transmission-url`, `/etc/transmission-url`, `./transmission-url`.

### Running
When run, Transmission performs a sequence of steps:

* update-banner: Updates the TTY banner shown at login with info on the device management URL and device ID.
* create-users: Creates the users specified by the device manager, adding authorized SSH keys.
* stage-files: Downloads, decodes, uncompresses, and verifies files and systemd units into a staging area.
* update-configsets: Makes staged files the current config set, backing up the old current set beforehand.
* sync-root: Syncs the current configuration set to the root directory (i.e. activates the configuration).
* update-selinux: Updates the setenforce mode according to the configuration.
* update-systemd-units: Reloads the systemd daemon and enables/disables units as per the configuration.

Using the `--skip-step` and `--stop-after` options, it is possible to skip any of these steps or stop after a step, respectively. This is mainly for testing, but also to only update the banner.

Using the `--root-dir` option, one can tell Transmission to sync config not to the system root (`/`) directory but a changed root.

## Implementation Details
### Device Management Endpoint
Transmission will periodically query (via HTTP GET) the provided URL under the endpoint `{base_url}/netboot/{arch}/ignition/{device_id}`, whereby `{arch}` is the device's platform (output of `uname -i`) and `{device_id}` is a device identifier (currently the MAC address of the device's primary network interface). This is so it can serve as a drop-in replacement for Fedora's `zezere-ignition` agent.

### Device Management Protocol
Transmission currently uses the `Ignition` protocol for transporting changes, more specifically a subset of the Ignition v3.2.0 spec. Ignition was designed for machine provisioning and to be run from initramfs, where it can apply changes (like disk partitioning) that aren't easily done post-provisioning.

Transmission is currently limited to processing the following Ignition objects:
```
ignition/version
storage/files/path
storage/files/contents/compression
storage/files/contents/source
storage/files/contents/verification/hash
storage/files/mode
storage/files/user
storage/files/group
systemd/units/name
systemd/units/enabled
systemd/units/contents
systemd/units/contents/dropins
passwd/users/name
passwd/users/sshAuthorizedKeys
```

### Managing Configuration Sets
Transmission maintains the following diretory structure under `CONFIGSET_ROOT` (by default `/var/opt/transmission/configsets`):
```
CONFIGSET_ROOT
├── staging
├── [next]
├── current
├── last
└── [lastlast]
```
Whereby `staging` contains the - possibly incomplete and later retried - set of configuration files. If the Ignition config contains verfication hashes, Transmission will use those to detect unmodified and already downloaded assets and will avoid downloading them again.

When staging holds a complete, verfied set of assets, Transmission will sync them to a (temporary) `next` directory, and then start rotating configuration sets `next`🠖`current`🠖`last`🠖`lastlast`, finally deleting `lastlast`. Finally, it syncs the `current` set with the system's root dir, relabeling SELinux contexts as necessary.

### Managing SELinux Mode
Should a user modify `/etc/selinux/config` to change the default SELinux state of the system, Transmission calls `setenforce` to effect this change immediately (without having to reboot).

### Managing `systemd` Updates
Transmission can automatically reload or restart `systemd` units or reboot the system when configuration changes that requires these actions. This works by creating one or more of these files
* `/etc/transmission.d/units_requiring_reload.yaml`
* `/etc/transmission.d/units_requiring_restart.yaml`
* `/etc/transmission.d/units_requiring_reboot.yaml`

and adding a dictionary of `{"unit_name": ["glob_pattern_1", "glob_pattern_2", ...]}` to it, for example:
```
demo.service:
  - /var/opt/demo/*
  - /etc/demo/*.conf
```