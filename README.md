# Transmission
## About
Transmission is an experimental device management agent for `ostree`-based Linux operating systems.

It manages device configuration similar to `ostree` managing a device OS: It periodically queries a configuration service for updates to a device's target configuration. If updates exists, it stages these updates as a new configuration set, including downloading assets and verifying their integrity, and then transactionally rolls that updated configuration set into the device's live file system, reloading 'systemd' units that depend on changed configuration as necessary. Transmission also supports rolling back configuration, for example triggered by [greenboot](https://github.com/fedora-iot/greenboot) health checking scripts.

As configuration servivce, Transmission supports a GitHub provider that makes it very easy to manage devices in a GitOps methodology as well as an Ignition provider that would allow configuration to be served in a manner similar to OpenShift’s MachineConfigServer.

Transmission now also supports managing container workloads on Podman, but adding/updating/removing pod manifests in `/etc/transmission.d/pod-manifests`.

## Usage
### Installation
Transmission comes as `.rpm` file and is meant to be included into the `ostree` image, e.g. by including it into `OSBuilder` blueprints. It will install a `systemd timer` to run periodically every 5 minutes by default.

Users need to provide Transmission with the URL of the device management service to query for updates, either by supplying the `transmission.url` kernel argument or by writing this URL to one of the following locations (which it will search in order): `/usr/lib/transmission-url`, `/etc/transmission-url`, `./transmission-url`.

### Running
Transmission supports the following commands:

* `transmission update` queries Transmission's management endpoint for updates and stages any changes locally, before applying them to the current configuration set and activating it by syncing to the root file system.
* `transmission rollback` makes the previous configuration set the current configuration set and activates it by syncing to the root file system.

In this process, Transmission performs a sequence of steps:

* update-banner: Updates the TTY banner shown at login with info on the device management URL and device ID.
* stage-files: Downloads, decodes, uncompresses, and verifies files and systemd units into a staging area.
* create-users: Creates the users specified by the device manager, adding authorized SSH keys.
* update-configsets: Makes staged files the current config set, backing up the previous configuration set beforehand.
* apply-configsets: Syncs the current configset to the root file system.
* update-selinux: Updates the setenforce mode according to the configuration.
* update-systemd-units: Reloads the systemd daemon and enables/disables/reloads/... units as per the configuration.

Using the `--skip-step` and `--stop-after` options, it is possible to skip any of these steps or stop after a step, respectively. This is mainly for testing, but also to only update the banner.

Using the `--root-dir` option, one can tell Transmission to sync config not to the system root (`/`) directory but a changed root.

You can increase the log-level using the `--log-level` argument.

## Implementation Details
### Device Management Endpoint
Transmission will periodically query (via HTTP GET) the provided URL, making the following variable substitutions:
* `${arch}`: the device's platform (output of `uname -i`)
* `${mac}`: the MAC address of the device's primary interface
* `${uuid}`: a UUID generated based on `/etc/machine-id`
* `${subscriptionid}`: the Red Hat Subscription Manager ID (from `subscription-manager identity`)
* `${insightsid}`: the Red Hat Insights ID (from `/etc/insights-client/machine-id`)

For example, to serve as drop-in replacement for Fedora's `zezere-ignition` agent, one would use a URL like `http://my.zezere-service.net/netboot/${arch}/ignition/${mac}`.

### Device Management Protocol
Transmission currently supports two protocols for transporting changes:

By default, it uses the `Ignition` protocol for transporting changes, more specifically a subset of the Ignition v3.2.0 spec. Ignition was designed for machine provisioning and to be run from initramfs, where it can apply changes (like disk partitioning) that aren't easily done post-provisioning.

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

Alternatively, if the URL points to a repo on `github.com`, Transmission clones that repo, optionally checks out the ref provided by the `?ref=` parameter and then periodically pulls updates. Contents of that repo are assumed to be relative to the root filesystem. Files ending in `.meta` are interpreted as Ignition file spec and can be used to download additional assets.

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

When staging holds a complete, verfied set of assets, Transmission will sync them to a (temporary) `next` directory, and then start rotating configuration sets `next` --> `current` --> `last` --> `lastlast`, finally deleting `lastlast`. Finally, it syncs the `current` set with the system's root dir, relabeling SELinux contexts as necessary.

Similarly, a rollback means rotating `last` --> `current` and syncing the `current` set with the system's root dir, relabeling SELinux contexts again.

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