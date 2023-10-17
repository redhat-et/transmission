# Transmission
## About

Transmission is a GitOps-driven device management agent [ostree-based](https://github.com/ostreedev/ostree) Linux systems.

It periodically queries a specified [GitHub](https://coreos.github.io/ignition/) repo or [Ignition](https://coreos.github.io/ignition/) configuration server for the device's target configuration. Updates are staged into a "config set" and applied transactionally into the device's live file system, reloading 'systemd' units that depend on changed configuration as necessary. Transmission also supports rolling back configuration, for example triggered by [greenboot](https://github.com/fedora-iot/greenboot) health checking scripts.

## Usage
### Installation

Transmission comes as `.rpm` file and is meant to be included into the `ostree` image, e.g. by including it into [OSBuild](https://www.osbuild.org/) image blueprints. It will install a `systemd timer` to run periodically every 5 minutes by default.

Users need to provide Transmission with the URL of the device management service to query for updates, either by supplying the `transmission.url` kernel argument or by writing this URL to one of the following locations (which it will search in order): `/usr/lib/transmission-url`, `/etc/transmission-url`, `./transmission-url`.

### Running

Transmission supports the following commands:

* `transmission update` queries Transmission's management endpoint for updates and stages any changes locally, before applying them to the current configuration set and activating it by syncing to the root file system.
* `transmission rollback` makes the previous configuration set the current configuration set and activates it by syncing to the root file system.
* `transmission update-banner` updates the console banner to display the management endpoint's URL.

If run as a non-root user, instead of updating the root file system it uses `$HOME/.transmission` dir to simulate an update.

## Implementation Details
### Device Management Endpoint

Transmission will periodically query (via HTTP GET) the provided URL, making the following variable substitutions:
* `${arch}`: the device's platform (output of `uname -m`)
* `${mac}`: the MAC address of the device's primary interface
* `${uuid}`: a UUID generated based on `/etc/machine-id`
* `${subscriptionid}`: the Red Hat Subscription Manager ID (from `subscription-manager identity`)
* `${insightsid}`: the Red Hat Insights ID (from `/etc/insights-client/machine-id`)

For example, to serve as drop-in replacement for Fedora's `zezere-ignition` agent, one would use a URL like `http://my.zezere-service.net/netboot/${arch}/ignition/${mac}`.

### Device Management Protocol

Transmission currently supports two protocols for transporting changes:

By default, it uses the [Ignition](https://coreos.github.io/ignition/specs/) protocol for transporting changes, more specifically a subset of the Ignition v3.2.0 spec. Ignition was designed for machine provisioning and to be run from initramfs, where it can apply changes (like disk partitioning) that aren't easily done post-provisioning.

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
Transmission maintains the following diretory structure under `/etc/transmission`:

```
/etc/transmission
├── staging
├── configsets
│   ├── desired.ign
│   ├── current.ign
│   └── previous.ign
├── noorig
└── orig
```

Config sets are bundles of configuration files, in [Ignition](https://coreos.github.io/ignition/specs/) format, that get transactionally applied. `desired.ign` is the new target configuration, `current.ign` the currently running configuration, `previous.ign` the configuration before the last update.

If config sets need to be assembled from multiple files (e.g. git repo) or referenced external files, Transmission uses the `staging` repo as a work area.

The `orig` and `noorig` directories are for backing up and reverting replaced system files.

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

### Managing Containers on Podman
To declaratively manage containers on the device, users can place Kubernetes pod spec manifests into `/etc/transmission.d/pod-manifests` that Transmission will then automatically run on Podman using `podman play kube`. Refer to the [Podman documentation](https://docs.podman.io/en/latest/markdown/podman-play-kube.1.html) for the pod spec constructs that Podman supports. When a manifest is updated or removed, the corresponding pod is replaced or deleted, respectively.