#!/usr/bin/python

import argparse
import os
import re
import subprocess
import sys

priority=['scx_stats', 'scx_stats_derive', 'scx_utils', 'scx_rustland_core', 'scx_p2dq']
skip=['scx_mitosis']
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

def get_rust_paths():
    result = subprocess.run(['git', 'ls-files'], stdout=subprocess.PIPE)
    lines = result.stdout.decode('utf-8').splitlines()
    paths = []
    for line in lines:
        if line.endswith('Cargo.toml'):
            paths.append(line)
    return paths

def cargo_path_to_crate(path):
    return path.split('/')[-2]

def cargo_is_workspace(path):
    with open(path, 'r') as f:
        lines = f.readlines()

    for lineno, line in enumerate(lines):
        workspace_re = r'(^\s*)(\[\s*workspace\s*\])(.*$)'

        m = re.match(workspace_re, line)
        if m:
            dbg(f'[{path}:{lineno}] SKIP: {m.group(1)}{underline(m.group(2))}{m.group(3)}')
            return True

    return False

def publish(path, extra_args, ignore_existing):
    directory = os.path.dirname(path)
    try:
        proc = subprocess.run(['cargo', 'publish'] + extra_args, cwd=directory,
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

    paths = get_rust_paths()
    crate_path_args = {}
    for path in paths:
        if cargo_is_workspace(path):
            continue

        crate = cargo_path_to_crate(path)
        pargs = []

        if crate in publish_args:
            pargs = publish_args[crate]
            del publish_args[crate]

        crate_path_args[crate] = [path, pargs]

    if len(publish_args):
        err(f'publish_args contains non-existent crates {publish_args}')

    if args.start and args.start not in crate_path_args:
        err(f'--start specified non-existent crate {args.start}')

    for crate in skip:
        if crate not in crate_path_args:
            err(f'{crate} is in skip list but does not exist')
        del crate_path_args[crate]

    # Fill targets in publishing order
    targets = []

    for pri in priority:
        if pri not in crate_path_args:
            err(f'cannot find cargo path for priority crate {pri}')
        path_args = crate_path_args[pri]
        targets.append([pri, [path_args[0], path_args[1]]])
        del crate_path_args[pri]

    for crate, path_args in sorted(crate_path_args.items()):
        targets.append([crate, [path_args[0], path_args[1]]])

    # Publish
    start_from = args.start
    for target in targets:
        if start_from and target[0] != start_from:
            continue
        start_from = None

        print(f'Publishing crate {target[0]} {" ".join(target[1][1])}')
        dbg(f'target: {target}')
        if not args.dry:
            publish(target[1][0], target[1][1], args.ignore)

main()
