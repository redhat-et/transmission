#!/usr/bin/python3

from typing import Optional, List

import argparse
import base64
import gzip
import hashlib
import json
import os
import platform
import shutil
import sys
import urllib.request

DEFAULT_TRANSMISSION_URL = "http://device-management.redhat.edge-lab.net"
MACHINE_ID = "14:7d:da:9b:80:bd"
ACTIVE_DIR = "/Users/fzdarsky/Development/transmission/target/active"
STAGING_DIR = "/Users/fzdarsky/Development/transmission/target/staging"


def get_transmission_url():
    return DEFAULT_TRANSMISSION_URL


def get_machine_id():
    return MACHINE_ID


def fetch_from_data(dest, url):
    print(f"  fetch from data URL")
    data = url.split("base64,")[1]
    data = base64.b64decode(data)
    with open(dest, 'wb') as f:
        f.write(data)


def fetch_from_http(dest, url):
    print(f"  fetch from {url}")
    urllib.request.urlretrieve(url, dest) 


fetchers = {
    'data': fetch_from_data,
    'http': fetch_from_http,
    'https': fetch_from_http
}


def fetch(dest, url):
    scheme = url.split(':')[0]
    if scheme in fetchers:
        if not os.path.exists(os.path.dirname(dest)):
            os.makedirs(os.path.dirname(dest), exist_ok=True)
        fetchers[scheme](dest, url)
    else:
        print(f"  fetch: unkown scheme {scheme} --> skipping!")


def decompress_gzip(dest):
    print(f"  decompress (gzip)")
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
        print(f"  decompress: unknwon compression {compression} --> skipping!")
    

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


def compute_hash(dest, target_hash):
    hash_type = get_hash_type(target_hash)
    if hash_type in hashers:
        actual_hash = hashers[hash_type](dest)    
        with open(dest+"."+hash_type, 'w') as f:
            f.write(get_hash_digest(actual_hash))
        print(f"  hash is {actual_hash}")
        return actual_hash
    else:
        print(f"  hash: unknown hash type {hash_type}")
        return ""


def check_hash(dest, target_hash):
    hash_type = get_hash_type(target_hash)
    with open(dest+"."+hash_type, 'r') as f:
        return f.read() == get_hash_digest(hash)
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


def stage_file(f):
    target_path = f.get("path")
    if target_path.startswith("/"):
        target_path = target_path[1:]

    target_hash = f.get("contents", {}).get("verification", {}).get("hash", "")

    # hack until DM removes base64 encoding
    if target_hash and not (target_hash.startswith("sha256") or target_hash.startswith("sha512")):
        target_hash=""

    print(f"staging {target_path} ({target_hash}):")

    dest = STAGING_DIR + '/' + target_path
    if is_staged(dest, target_hash):
        print(f"  already staged (skipping)")
        return False, False

    url = f.get("contents", {}).get("source", "")
    fetch(dest, url)

    compression = f.get("contents", {}).get("compression", "null")
    decompress(dest, compression)

    if target_hash:
        actual_hash = compute_hash(dest, target_hash)
        if actual_hash != target_hash:
            print(f"  hash checksum mismatch ({actual_hash} != {target_hash})")
            return True, True
    return False, True


def stage_files(ignition):
    staging_failed = False
    staging_had_updates = False
    for f in ignition.get("storage", {}).get("files", []):
        failed, updated = stage_file(f)
        staging_failed |= failed
        staging_had_updates |= updated
    return staging_failed, staging_had_updates


def apply_ignition(ignition):
    staging_failed, staging_had_updates = stage_files(ignition)
    print(f"apply ignition: failures {staging_failed}, updates {staging_had_updates}")


def main(args: argparse.Namespace):
    transmission_url = get_transmission_url()
    machine_id = get_machine_id()
    arch = platform.machine()

    url = "%s/netboot/%s/ignition/%s" % (transmission_url, arch, machine_id)
    with urllib.request.urlopen(url) as f:
        ignition = json.loads(f.read().decode())
        apply_ignition(ignition)


def get_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Transmission")
    return parser.parse_args(argv)


if __name__ == "__main__":
    main(get_args(sys.argv[1:]))
