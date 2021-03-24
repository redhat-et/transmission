#!/usr/bin/env python3

from typing import Optional, List

import argparse
import base64
import gzip
import hashlib
import logging
import json
import os
import platform
import pwd
import shutil
import stat
import subprocess
import sys
import urllib.request
import yaml


# Where Transmission stores its own configs
DEFAULT_TRANSMISSION_CONFIG_DIR = "/etc/transmission.d"
# Where Transmission stores config sets
DEFAULT_TRANSMISSION_CONFIGSET_DIR = "/var/lib/transmission/configsets"
# The dir to sync config to
DEFAULT_ROOT_DIR = "/"
# Where Transmission places systemd units
DEFAULT_SYSTEMD_DIR = "/etc/systemd/system"

# Commands supported by Transmission
COMMANDS = [
    "update", "rollback", "update-banner"
]

# Steps performed by Transmission
ALLOWED_STEPS = [
    "update-banner",
    "stage-updates",
    "create-users",
    "update-configset",
    "apply-configset",
    "update-selinux",
    "update-systemd-units",
]

# Transmission only syncs to /etc and /var
SYNC_ALLOW_LIST = [
    "/etc/*",
    "/var/*"
]

# Transmission ignores hash files, changes to its state directory, and others
SYNC_DENY_LIST = [
    "*.sha256",
    "*.sha512",
    "*/.gitkeep",
    "/var/lib/transmission/*"
]



# -------------------- device ID and Transmission URL --------------------
# shamelessly plucked from https://github.com/fedora-iot/zezere/blob/main/zezere_ignition/__init__.py

def get_primary_interface() -> Optional[str]:
    mask_to_iface = {}

    with open("/proc/net/route", "r") as routefile:
        for line in routefile.readlines():
            if not line.strip():
                # Pass over empty lines
                continue
            split = line.split()
            interface = split[0]
            mask = split[7]
            if split[0] == "Iface":
                # Pass over the file header
                continue
            mask_to_iface[mask] = interface

    # If there are no routes at all, just exit
    if len(mask_to_iface) == 0:
        # No routes at all
        return None
    # Determine the smallest mask in the table.
    # This will default to the default route, or go further down
    return mask_to_iface[min(mask_to_iface, key=lambda x: int(x, 16))]


def get_interface_mac(interface: Optional[str]) -> str:
    if interface is None:
        return None
    with open("/sys/class/net/%s/address" % interface, "r") as addrfile:
        return addrfile.read().strip()


def get_device_id():
    return get_interface_mac(get_primary_interface())


def get_transmission_url_cmdline() -> Optional[str]:
    cmdline = None
    with open("/proc/cmdline", "r") as cmdlinefile:
        cmdline = cmdlinefile.read().strip()
    for arg in cmdline.split(" "):
        args = arg.split("=", 2)
        if len(args) != 2:
            continue
        key, val = args
        if key == "transmission.url" or key == "zezere.url":
            return val.strip()


def get_transmission_url():
    cmdline_url = get_transmission_url_cmdline()
    if cmdline_url is not None:
        return cmdline_url

    paths = [
        "/usr/lib/transmission-url",
        "/etc/transmission-url",
        "./transmission-url",
    ]
    for path in paths:
        if os.path.exists(path):
            with open(path, "r") as urlfile:
                return urlfile.read().strip()


# -------------------- helpers --------------------

def run_command(args):
    logging.debug(f"running command {args}")
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        env=os.environ.copy()
    )
    logging.debug(f"  return code: {result.returncode}")
    logging.debug(f"  stdout: '{result.stdout}'")
    logging.debug(f"    stderr: '{result.stderr}'")
    return result.returncode, result.stdout, result.stderr


def ensure_dir_exists(dirpath, mode=0o755, owner=''):
    if not os.path.exists(dirpath):
        os.makedirs(dirpath, exist_ok=True)
        if owner:
            shutil.chown(dirpath, user=owner, group=owner)
        os.chmod(dirpath, mode)


def hardlink_replacing(source, dest):
    if os.path.exists(dest):
        if os.lstat(source)[stat.ST_INO] == os.lstat(dest)[stat.ST_INO]:
            return # already hardlinked, nothing to do
        else:
            os.remove(dest) # delete existing file
    run_command(["ln", source, dest])


def copy_replacing(source, dest):
    run_command(["cp", "-fpZ", source, dest])


def get_ignition(url):
    logging.info(f"Requesting from {url}")
    with urllib.request.urlopen(url) as f:
        return json.loads(f.read().decode())


def matches_glob(string, glob="*"):
    parts = glob.split("*")
    if parts[0] and not string.startswith(parts[0]):
        return False
    if parts[-1] and not string.endswith(parts[-1]):
        return False
    return True


def matches_globs(string, globs):
    for glob in globs:
        if matches_glob(string, glob):
            return True
    return False


# -------------------- adding users --------------------

def user_exists(name):
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def get_user_home(name):
    try:
        return pwd.getpwnam(name).pw_dir
    except KeyError:
        return None


def create_users(ignition):
    for u in ignition.get("passwd", {}).get("users", []):
        name = u.get("name")
        if not user_exists(name):
            logging.info(f"create user {name}")
            cmd = [
                "/usr/sbin/useradd",
                "--create-home",
                name
            ]
            run_command(cmd)

        user_home = get_user_home(name)
        if not user_home:
            logging.warning(f"Failed to find user home for {name}")
            return

        keys = u.get("sshAuthorizedKeys", [])
        if keys:
            ssh_dir = user_home + "/.ssh"
            ensure_dir_exists(ssh_dir, 0o700, name)
            key_file = ssh_dir + '/authorized_keys'
            if not os.path.exists(key_file) or os.stat(key_file).st_size == 0:
                with open(key_file, 'w') as f:
                    for k in keys:
                        f.write(k)
                shutil.chown(key_file, user=name, group=name)
                os.chmod(key_file, 0o600)


# -------------------- staging assets --------------------

def fetch_from_data(dest, url):
    logging.debug(f"  fetch from data URL")
    data = url.split("base64,")[1]
    data = base64.b64decode(data)
    with open(dest, 'wb') as f:
        f.write(data)


def fetch_from_http(dest, url):
    logging.debug(f"  fetch from {url}")
    urllib.request.urlretrieve(url, dest) 


fetchers = {
    'data': fetch_from_data,
    'http': fetch_from_http,
    'https': fetch_from_http
}


def fetch(dest, url):
    scheme = url.split(':')[0]
    if scheme in fetchers:
        ensure_dir_exists(os.path.dirname(dest))
        fetchers[scheme](dest, url)
    else:
        logging.debug(f"  fetch: unkown scheme {scheme} --> skipping!")


def decompress_gzip(dest):
    logging.debug(f"  decompress (gzip)")
    with gzip.open(dest, 'rb') as f_in:
        with open(dest + ".tmp", 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)
    shutil.move(dest + ".tmp", dest)


def decompress_null(dest):
    return


decompressors = {
    'gzip': decompress_gzip,
    'null': decompress_null
}


def decompress(dest, compression):
    if compression in decompressors:
        decompressors[compression](dest)
    else:
        logging.debug(f"  decompress: unknwon compression {compression} --> skipping!")
    

def hash_sha256(dest):
    with open(dest, 'rb') as f:
        return "sha256-" + hashlib.sha256(f.read()).hexdigest()


def hash_sha512(dest):
    with open(dest, 'rb') as f:
        return "sha512-" + hashlib.sha512(f.read()).hexdigest()


hashers = {
    'sha256': hash_sha256,
    'sha512': hash_sha512
}


def get_hash_type(hash):
    return hash.split('-')[0]


def get_hash_digest(hash):
    return hash.split('-')[1]


def abbrev_hash(hash, max_length=32):
    if len(hash) > max_length:
        return hash[0:max_length] + "..."
    return hash


def compute_hash(dest, target_hash):
    hash_type = get_hash_type(target_hash)
    if hash_type in hashers:
        actual_hash = hashers[hash_type](dest)    
        with open(dest+"."+hash_type, 'w') as f:
            f.write(get_hash_digest(actual_hash))
        return actual_hash
    else:
        logging.debug(f"  hash: unknown hash type {hash_type}")
        return ""


def check_hash(dest, target_hash):
    hash_type = get_hash_type(target_hash)
    with open(dest+"."+hash_type, 'r') as f:
        return f.read() == get_hash_digest(target_hash)
    return False


# a file is considered 'staged' if it
#  * exists in the right path/filename under the staging dir and
#  * if a target_hash has been provided, the file's hash matches the target
def is_staged(dest, target_hash):
    if not os.path.exists(dest):
        return False

    if target_hash:
        hash_type = target_hash.split('-')[0]
        if not os.path.exists(dest+"."+hash_type):
            compute_hash(dest, hash_type)
        return check_hash(dest, target_hash)

    return True


def update_file_owner_mode(dest, f):
    user = os.geteuid()
    user = f.get("user", {}).get("id", user)
    user = f.get("user", {}).get("user", user)

    group = os.getegid()
    group = f.get("group", {}).get("id", group)
    group = f.get("group", {}).get("user", group)

    mode = f.get("mode", 420)

    logging.debug(f"  change file owner to {user}:{group}, mode to {mode:#o}")
    if int(mode) > 0o777:
        logging.warning(f"    warning: did you forget to specify file mode in _decimal_?")

    shutil.chown(dest, user=user, group=group)
    os.chmod(dest, mode)


def stage_file(f, configset_dir):
    target_path = f.get("path")
    if not target_path.startswith("/"):
        target_path = f"/{target_path}"

    target_hash = f.get("contents", {}).get("verification", {}).get("hash", "")

    logging.debug(f"staging {target_path} ({abbrev_hash(target_hash)})")

    dest = configset_dir + '/staging' + target_path
    if is_staged(dest, target_hash):
        logging.debug(f"  already staged --> skipping")
        return False, None

    url = f.get("contents", {}).get("source", "")
    fetch(dest, url)

    compression = f.get("contents", {}).get("compression", "null")
    decompress(dest, compression)

    update_file_owner_mode(dest, f)

    if target_hash:
        actual_hash = compute_hash(dest, target_hash)
        if actual_hash != target_hash:
            logging.warn(f"  hash mismatch ({actual_hash} != {target_hash})")
            return True, None
        else:
            logging.debug(f"  hash matches")
    return False, target_path


def stage_systemd_unit(u, configset_dir):
    ensure_dir_exists(configset_dir + '/staging' + DEFAULT_SYSTEMD_DIR)
    unitname = u.get("name", "unnamed.unit")
    unitfile = configset_dir + '/staging' + DEFAULT_SYSTEMD_DIR + "/" + unitname
    with open(unitfile, 'w') as f:
        f.write(u.get("contents", ""))

    for d in u.get("dropins", []):
        ensure_dir_exists(unitfile + ".d")
        dropinname = d.get("name", "unnamed-dropin.conf")
        dropinfile = unitfile + ".d/" + dropinname
        with open(dropinfile, 'w') as f:
            f.write(d.get("contents", ""))

    return {unitname: u.get("enabled")}


def stage_files(ignition, configset_dir):
    errors = False
    changed_files = []
    changed_systemd_units = {}
    for f in ignition.get("storage", {}).get("files", []):
        error, changed_file = stage_file(f, configset_dir)
        errors |= error
        if changed_file:
            changed_files.append(changed_file)
    for u in ignition.get("systemd", {}).get("units", []):
        changed_systemd_unit = stage_systemd_unit(u, configset_dir)
        changed_systemd_units.update(changed_systemd_unit)
    return errors, changed_files, changed_systemd_units


# -------------------- applying configuration sets --------------------

def files_to_sync(source, to_rootfs=False):
    files_to_sync = []
    for root, _, files in os.walk(source):
        root = root[len(source):]
        for f in files:
            path = os.path.join(root, f)
            # only sync files on allow list and not on deny list
            if matches_globs(path, SYNC_ALLOW_LIST) and not matches_globs(path, SYNC_DENY_LIST):
                files_to_sync.append(path)
            # in configsets (i.e. not copying to rootfs), also sync Transmission state files
            if not to_rootfs and path.startswith(".transmission"):
                files_to_sync.append(f"/{path}")
    return files_to_sync


def sync_configset(source, dest, to_rootfs=False, relabel=False):
    updated_files = []

    for f in files_to_sync(source, to_rootfs):
        logging.debug(f"syncing {source + f} to {dest + f}")
        ensure_dir_exists(os.path.dirname(dest + f))
        if to_rootfs and f"{dest + f}".startswith("/etc"):
            # can't hardlink across devices (from /var to /etc), so copy instead
            copy_replacing(source + f, dest + f)
        else:
            hardlink_replacing(source + f, dest + f)
        if relabel:
            run_command(["restorecon", dest + f])
        updated_files.append(f)

    return updated_files


def update_configset(configset_dir):
    logging.info("Updating configset")

    run_command(["rm", "-rf", configset_dir + "/next"])
    run_command(["mkdir", configset_dir + "/next"])
    sync_configset(configset_dir + "/staging", configset_dir + "/next")
    
    run_command(["mv", configset_dir + "/last", configset_dir + "/lastlast"])
    run_command(["mv", configset_dir + "/current", configset_dir + "/last"])
    run_command(["mv", configset_dir + "/next", configset_dir + "/current"])
    run_command(["rm", "-rf", configset_dir + "/lastlast"])


def rollback_configset(configset_dir):
    logging.info("Rolling back configset")

    if not os.path.exists(configset_dir + "/last"):
        return "No previous configset to roll back to."

    run_command(["rm", "-rf", configset_dir + "/current"])
    run_command(["mv", configset_dir + "/last", configset_dir + "/current"])
    return None


# -------------------- updating selinux --------------------

def update_selinux():
    logging.info("Updating SELinux")
    if os.path.exists("/etc/selinux/config"):
        enforce = 1
        with open("/etc/selinux/config", "r") as f:
            for line in f:
                line = line.strip().lower()
                if line.startswith("selinux="):
                    if line.split("=")[1] == "permissive":
                        enforce = 0
                    break
        run_command(["setenforce", str(enforce)])


# -------------------- updating systemd units --------------------

def get_units_requiring(action, changed_files):
    units = []

    reqs_file = DEFAULT_TRANSMISSION_CONFIG_DIR + f"/units_requiring_{action}.yaml"
    if not os.path.exists(reqs_file):
        return units

    reqs = {}
    with open(reqs_file, "r") as f:
        try:
            reqs = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logging.error(f"Error parsing {reqs_file}: {e} --> skipping.")
            return units

    for unit in reqs.keys():
        globs = reqs.get(unit, [])
        if not isinstance(globs, list):
            logging.error(f"Error parsing {reqs_file}: unit {unit} needs to map to list of globs --> skipping")
            continue
        for f in changed_files:
            if matches_globs(f, globs):
                units.append(unit)
    return units


def update_systemd_units(changed_files, units):
    # reload systemd to make it aware of new units
    run_command(["systemctl", "daemon-reload"])

    # enable/disable units according to config
    for unit, enabled in units.items():
        if enabled is None: # Ignition defines 'None' as "no change"
            continue
        if enabled:
            run_command(["systemctl", "enable", unit])
            run_command(["systemctl", "start", unit])
        else:
            run_command(["systemctl", "disable", unit])
            run_command(["systemctl", "stop", unit])

    # check which units require reloading and reload them
    for unit in get_units_requiring("reload", changed_files):
        logging.info(f"Reloading systemd unit {unit}.")
        run_command(["systemctl", "reload", unit])

    # check which units require restarting and restart them
    for unit in get_units_requiring("restart", changed_files):
        logging.info(f"Restarting systemd unit {unit}.")
        run_command(["systemctl", "restart", unit])

    # check whether units require rebooting and reboot accordingly
    units_requiring_reboot = get_units_requiring("reboot", changed_files)
    if units_requiring_reboot:
        logging.info(f"Rebooting system as required by {units_requiring_reboot}.")
        run_command(["systemctl", "reboot"])

    return


# -------------------- banner updates --------------------

def update_banner(url: str, device_id: Optional[str]):
    if device_id is None:
        device_id = "device ID not yet known"
    with open("/run/transmission-banner", "w") as bannerfile:
        bannerfile.write(
            f"Using {url} to provision this device ({device_id})\n\n"
        )


# -------------------- argparse and main --------------------

def main(args: argparse.Namespace):
    # initialize logging
    numeric_log_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_log_level, int):
        raise ValueError('Invalid log level: %s' % args.log_level)
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=numeric_log_level)

    # determine URL of the transmission server and the client's device ID
    transmission_url = get_transmission_url()
    if not transmission_url:
        logging.error("No Transmission URL configured, exiting")
        return

    device_id = get_device_id()

    # even if the device ID isn't available yet, we can update the banner
    if "update-banner" not in args.steps_to_skip:
        update_banner(transmission_url, device_id)
        if "update-banner" == args.stop_after_step:
            return

    if device_id is None:
        logging.warning("Unable to determine default interface, exiting")
        return

    if args.command == "rollback":
        # roll back configset, making the last one current
        error = rollback_configset(args.configset_dir)
        if error:
            logging.error(f"Error rolling back configset: {error}")
            return

    elif args.command == "update":
        # check for updates and stage them
        ignition = get_ignition(
            f"{transmission_url}/netboot/{platform.machine()}/ignition/{device_id}")
        if not ignition:
            logging.warning("Unable to retrieve Ignition config, exiting")
            return

        has_errors, has_changes = False, False
        if "stage-updates" not in args.steps_to_skip:
            has_errors, has_changes = stage_updates(ignition, args.configset_dir + "/staging")
            if "stage-updates" == args.stop_after_step:
                return

        # even if some files failed download, create users
        if "create-users" not in args.steps_to_skip:
            create_users(ignition)
            if "create-users" == args.stop_after_step:
                return

        # if staging failed, stop here and retry later
        if has_errors:
            logging.warning("One or more files couldn't be staged, exiting")
            return
        # if staging completed without changes, stop here and retry later
        if not has_changes:
            logging.info("No updates, exiting")
            return

        # if staging completed with changes, update the current config set
        if  "update-configset" not in args.steps_to_skip:
            update_configset(args.configset_dir)
            if "update-configset" == args.stop_after_step:
                return
    else:
        return

    # apply current configset and update selinux and systemd accordingly
    if  "apply-configset" not in args.steps_to_skip:
        updated_files = sync_configset(args.configset_dir + "/current", args.root_dir, to_rootfs=True, relabel=True)
        if "apply-configsets" == args.stop_after_step:
            return

        if  "update-selinux" not in args.steps_to_skip:
            if "/etc/selinux/config" in updated_files:
                update_selinux()
            if "update-selinux" == args.stop_after_step:
                return

        if  "update-systemd-units" not in args.steps_to_skip:
            update_systemd_units(args.configset_dir + "/current", updated_files)
            if "update-systemd-units" == args.stop_after_step:
                return


def get_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "command",
        choices=COMMANDS,
        help="update/rollback the current configset or only update banner and exit",
    )
    parser.add_argument(
        "--skip-step",
        dest="steps_to_skip",
        action="append",
        type=str,
        choices=ALLOWED_STEPS,
        help=f"skip this step (can be used multiple times)",
    )
    parser.add_argument(
        "--stop-after",
        dest="stop_after_step",
        action="store",
        type=str,
        choices=ALLOWED_STEPS,
        help=f"stop after this step",
    )
    parser.add_argument(
        "--configset-dir",
        dest="configset_dir",
        action="store",
        type=str,
        help=f"directory for storing config sets",
        default=DEFAULT_TRANSMISSION_CONFIGSET_DIR,
    )
    parser.add_argument(
        "--root-dir",
        dest="root_dir",
        action="store",
        type=str,
        help=f"root directory to sync config sets to",
        default=DEFAULT_ROOT_DIR,
    )
    parser.add_argument(
        "--log-level",
        dest="log_level",
        action="store",
        type=str,
        choices=["error", "warning", "info", "debug"],
        help=f"log level to use in log output",
        default="info",
    )

    args = parser.parse_args(argv)
    if args.steps_to_skip is None:
        args.steps_to_skip = []
    return args


if __name__ == "__main__":
    main(get_args(sys.argv[1:]))
