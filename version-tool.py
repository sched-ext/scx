#!/usr/bin/python

import argparse
import json
import os
import re
import subprocess
import sys

verbose = False

def warn(line):
    print('[WARN] ' + line, file=sys.stderr)

def err(line):
    raise Exception(line)

def dbg(line):
    if verbose:
        print('[DBG] ' + line, file=sys.stderr)

def underline(string):
    return f'\033[4m{string}\033[0m'

def do_meson_ver(new_ver):
    path = 'meson.build'
    with open(path, 'r') as f:
        lines = f.readlines()

    ver_lineno = -1
    for lineno, line in enumerate(lines):
        ver_re = r"(^.*version:\s*')([0-9.]*)('.*$)"
        m = re.match(ver_re, line.rstrip())
        if m:
            ver_lineno = lineno
            pre = m.group(1)
            ver = m.group(2)
            post = m.group(3)
            dbg(f'[{path}:{lineno+1}] {pre}{underline(ver)}{post}')
            break

    if ver_lineno < 0:
        err(f'[{path}] Failed to find verion')

    if new_ver is None or ver == new_ver:
        return ver

    print(f'[{path}:{ver_lineno+1}] Updating from {ver} to {new_ver}')
    lines[ver_lineno] = f'{pre}{new_ver}{post}\n'
    with open(path, 'w') as f:
        f.writelines(lines)

    return ver

def get_rust_paths():
    result = subprocess.run(['git', 'ls-files'], stdout=subprocess.PIPE)
    lines = result.stdout.decode('utf-8').splitlines()
    paths = []
    for line in lines:
        # ignore root Cargo.toml
        if line.endswith('Cargo.toml') and '/' in line:
            paths.append(line)
    return paths

def cargo_path_to_crate(path):
    return path.split('/')[-2]

def do_rust_ver(path, new_ver):
    with open(path, 'r') as f:
        lines = f.readlines()

    name_lineno = -1
    ver_lineno = -1
    name = None
    ver = None
    for lineno, line in enumerate(lines):
        workspace_re = r'(^\s*)(\[\s*workspace\s*\])(.*$)'
        name_re = r'(^\s*name\s*=\s*")(.*)(".*$)'
        ver_re = r'(^\s*version\s*=\s*")(.*)(".*$)'
        line = line.rstrip()

        m = re.match(workspace_re, line)
        if m:
            dbg(f'[{path}:{lineno}] SKIP: {m.group(1)}{underline(m.group(2))}{m.group(3)}')
            return None

        m = re.match(name_re, line)
        if m:
            name_lineno = lineno
            name = m.group(2)
            dbg(f'[{path}:{lineno+1}] {m.group(1)}{underline(name)}{m.group(3)}')
        else:
            m = re.match(ver_re, line)
            if m:
                ver_lineno = lineno
                pre = m.group(1)
                ver = m.group(2)
                post = m.group(3)
                dbg(f'[{path}:{lineno+1}] {pre}{underline(ver)}{post}')

        if name_lineno >= 0 and ver_lineno >= 0:
            break

    if name_lineno < 0 or ver_lineno < 0:
        err(f'[{path}] Failed to find name or version')

    if name != cargo_path_to_crate(path):
        warn(f'[{path}:{name_lineno}] name \"{name}\" does not match the path')

    if new_ver is None or ver == new_ver:
        return ver

    print(f'[{path}:{ver_lineno+1}] Updating from {ver} to {new_ver}')
    lines[ver_lineno] = f'{pre}{new_ver}{post}\n'
    with open(path, 'w') as f:
        f.writelines(lines)

    return ver

def do_rust_deps(path, deps, new_deps):
    with open(path, 'r') as f:
        lines = f.readlines()

    in_dep = None
    block_depth = 0
    crate = None
    need_write = False

    for lineno, line in enumerate(lines):
        line = line.rstrip()

        # determine whether in a dependencies section
        sect_re = r'^\s*\[([^\[\]]*)]\s*$'
        m = re.match(sect_re, line)
        if m:
            if block_depth != 0:
                err(f'[{path}:{lineno+1}] Unbalanced block_depth {block_depth}');

            sect = m.group(1).strip()
            if sect.endswith('dependencies'):
                dbg(f'[{path}{lineno+1}] [{sect}]')
                in_dep = sect
            else:
                in_dep = None
            continue

        if not in_dep:
            continue

        # strip and store comment
        body = line
        comment_re = r'(^.*)(#.*$)'
        comment = ""
        m = re.match(comment_re, body)
        if m:
            body = m.group(1)
            comment = m.group(2)

        if len(body.strip()) == 0:
            continue

        # determine the current crate
        if block_depth == 0:
            crate_re = r'^\s*([^=\s]*)\s*=.*$'
            m = re.match(crate_re, body)
            if m:
                crate = m.group(1)
                crate_on_line = True
            else:
                warn(f'[{path}:{lineno+1}] Failed to find crate name')
                crate = None
        else:
            crate_on_line = False

        # do dumb nesting depth tracking
        block_depth += body.count('{') - body.count('}')
        block_depth += body.count('[') - body.count(']')

        if crate is None:
            continue

        # determine the crate version
        ver = None
        if crate_on_line:
            ver_re = r'(^[^=].*=\s*")([^"]*)("\s*$)'
            m = re.match(ver_re, body)
            if m:
                pre = m.group(1)
                ver = m.group(2)
                post = m.group(3)
        if ver is None:
            ver_re = r'(^.*version\s*=\s*")([^"]*)(".*$)'
            m = re.match(ver_re, body)
            if m:
                pre = m.group(1)
                ver = m.group(2)
                post = m.group(3)
        if ver is None:
            if block_depth == 0:
                warn(f'{path}:{lineno+1} no version')
            continue

        dbg(f'[{path}:{lineno+1}] {crate}: {pre}{underline(ver)}{post}')

        # check whether the version matches
        if crate in deps:
            if deps[crate] != ver:
                warn(f'[{path}:{lineno+1}] crate "{crate}" {ver} mismatches existing {deps[crate]}')
        else:
            deps[crate] = ver

        if crate in new_deps:
            new_ver = new_deps[crate]
            if ver != new_ver:
                print(f'[{path}:{lineno+1}] Updating dep {crate} = "{ver}" -> "{new_ver}"')
                lines[lineno] = f'{pre}{new_ver}{post}{comment}\n'
                need_write = True

        crate = None

    if block_depth != 0:
        err(f'[{path}:{lineno+1}] Unbalanced block_depth {block_depth}');

    if need_write:
        with open(path, 'w') as f:
            f.writelines(lines)

def main():
    parser = argparse.ArgumentParser(prog='version-tool.py',
                                     description='Check and update versions. "version-tool.py > vers.json" to generate the template. Apply the edited version with "version-too.py -u vers.json"')
    parser.add_argument('-u', '--update', metavar='JSON', type=str,
                        help='Update versions from the specified json file')
    parser.add_argument('-v', '--verbose', action='store_true')

    args = parser.parse_args()

    global verbose
    verbose = args.verbose

    vers_key = '00-versions'
    rust_vers_key = '01-rust-versions'
    rust_deps_key = '02-rust-deps'

    vers = {}
    rust_vers = {}
    rust_deps = {}

    new_vers = {}
    new_rust_vers = {}
    new_rust_deps = {}

    if args.update:
        with open(args.update, 'r') as f:
            parsed = json.loads(f.read())
            new_vers = parsed[vers_key]
            new_rust_vers = parsed[rust_vers_key]
            new_rust_deps = parsed[rust_deps_key]

    # package version
    vers['meson'] = do_meson_ver(new_vers.get('meson'))

    # rust crates implemented in the tree
    rust_paths = get_rust_paths()
    for path in rust_paths:
        name = cargo_path_to_crate(path)
        ver = do_rust_ver(path, new_rust_vers.get(name))
        if ver:
            rust_vers[name] = ver

    # crates implemented in the tree are included as deps by default
    rust_deps.update(rust_vers)
    new_rust_deps.update(new_rust_vers)

    # rust dependencies
    for path in rust_paths:
        do_rust_deps(path, rust_deps, new_rust_deps)

    # if not updating, print out what's read
    if args.update is None:
        for crate in rust_vers:
            rust_deps.pop(crate)

        manifest = { vers_key: vers,
                     rust_vers_key: rust_vers,
                     rust_deps_key: rust_deps }

        print(json.dumps(manifest, sort_keys=True, indent=4))

main()
