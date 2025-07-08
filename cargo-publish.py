#!/usr/bin/python

import argparse
import json
import re
import subprocess
import sys

publish_args={'scx_rlfifo': ['--no-verify'],
              'scx_rustland': ['--no-verify']}

verbose = False

def err(line):
    raise Exception(line)

def dbg(line):
    if verbose:
        print('[DBG] ' + line, file=sys.stderr)

def underline(string):
    return f'\033[4m{string}\033[0m'

def get_crate_info():
    metadata = subprocess.check_output(["cargo", "metadata", "--format-version", "1"])
    metadata = json.loads(metadata)

    default_members = set(metadata["workspace_default_members"])
    crates = {}

    for pkg in metadata["packages"]:
        if pkg.get("publish") == []:
            continue
        if pkg["id"] in default_members:
            deps = {dep["name"] for dep in pkg["dependencies"]
                   if dep["source"] is None and dep["kind"] != "dev"}
            crates[pkg["name"]] = deps

    return crates

def topological_sort(crates):
    in_degree = {name: len(deps) for name, deps in crates.items()}

    queue = [name for name, degree in in_degree.items() if degree == 0]
    result = []

    while queue:
        queue.sort()
        current = queue.pop(0)
        result.append(current)

        for name, deps in crates.items():
            if current in deps:
                in_degree[name] -= 1
                if in_degree[name] == 0:
                    queue.append(name)

    if len(result) != len(crates):
        remaining = [name for name in crates if name not in result]
        err(f'Circular dependency detected among crates: {remaining}')

    return result

def publish(crate, extra_args, ignore_existing):
    try:
        proc = subprocess.run(['cargo', 'publish', '-p', crate] + extra_args,
                              check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        stdout = e.stdout.decode('utf-8').splitlines()
        stderr = e.stderr.decode('utf-8').splitlines()

        okay = False
        if ignore_existing:
            already_re = r'(^.*)(crate.*already uploaded)(.*$)'
            m = re.match(already_re, stderr[-1])
            if m:
                print(f'IGNORE: {m.group(1)}{underline(m.group(2))}{m.group(3)}')
                okay = True

        if verbose or not okay:
            for line in stdout:
                print(f'STDOUT: {line}')
            for line in stderr:
                print(f'STDERR: {line}')
        if not okay:
            raise e

def main():
    parser = argparse.ArgumentParser(prog='cargo-publish.py',
                                     description='Publish rust projects, use --dry to see what it\'s going to do')
    parser.add_argument('-s', '--start',
                        help='skip crates which come before this crate in the publishing order')
    parser.add_argument('-i', '--ignore', action='store_true',
                        help='ignore errors from already published crates')
    parser.add_argument('-d', '--dry', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')

    args = parser.parse_args()

    global verbose
    verbose = args.verbose

    crates = get_crate_info()

    excess_publish_args = publish_args.keys() - crates.keys()
    if excess_publish_args:
        err(f'publish_args contains non-existent crates {excess_publish_args}')

    if args.start and args.start not in crates:
        err(f'--start specified non-existent crate {args.start}')

    targets = topological_sort(crates)

    # Publish
    start_from = args.start
    for target in targets:
        if start_from and target != start_from:
            continue
        start_from = None

        pargs = publish_args.get(target, [])
        print(f'Publishing crate {target} {" ".join(pargs)}')
        dbg(f'target: {target}')
        if not args.dry:
            publish(target, pargs, args.ignore)

main()
