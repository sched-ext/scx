#!/usr/bin/python3
import argparse
import sys
import json
import socket
import time
import tempfile
from prometheus_client import Gauge, CollectorRegistry, write_to_textfile
from pprint import pprint

verbose = 0

def info(line):
    print('[INFO] ' + line, file=sys.stderr)

def dbg(line):
    if verbose:
        print('[DBG] ' + line, file=sys.stderr)

def request(f, req, args={}):
    f.write(json.dumps({ 'req': req, 'args': args }) + '\n')
    f.flush()
    resp = json.loads(f.readline())
    if resp['errno'] != 0:
        raise Exception(f"req: {req} args: {args} failed with {resp['errno']} ({resp['args']['resp']})")
    return resp['args']['resp']

def make_om_metrics(sname, omid, field, labels, meta_db, registry):
    # @sname: The name of the current struct.
    #
    # @omid: The field path down from the top level struct. e.g. '.A.B'
    # means that the top level's field 'A' is a dict and the current one is
    # the field 'B' of the struct inside that dict.
    #
    # @field: The corresponding field part of the stats_meta.
    #
    # @labels: The collected $om_labels as this function descends down
    # nested dicts.

    # om_skip tells us that the server wants this field to be
    # skipped for OM.
    if 'user' in field and '_om_skip' in field['user']:
        dbg(f'skipping {omid} due to _om_skip')
        return {}

    desc = field['desc'] if 'desc' in field else ''
    prefix = meta_db[sname]['_om_prefix']

    if 'datum' in field:
        match field['datum']:
            # Single value that can become a Gauge. Gauge name is
            # $_om_prefix + the leaf level field name. The combination must
            # be unique.
            case 'i64' | 'u64' | 'float':
                gname = prefix + omid.rsplit('.', 1)[-1]
                dbg(f'creating OM metric {gname}@{omid} {labels} "{desc}"')
                return { omid: Gauge(gname, desc, labels, registry=registry) }
    elif 'dict' in field and 'datum' in field['dict'] and 'struct' in field['dict']['datum']:
        # The only allowed nesting is struct inside dict.
        sname = field['dict']['datum']['struct']
        struct = meta_db[sname]
        # $_om_label's will distinguish different members of the dict by
        # pointing to the dict keys.
        if not struct['_om_label']:
            raise Exception(f'{omid} is nested inside but does not have _om_label')
        # Recurse into the nested struct.
        oms = {}
        for fname, field in struct['fields'].items():
            oms |= make_om_metrics(sname, f'{omid}.{fname}', field,
                                   labels + [struct['_om_label']], meta_db, registry)
        return oms

    info(f'field "{omid}" has unsupported type, skipping')
    return {}

def update_om_metrics(resp, omid, labels, meta_db, om_metrics):
    for k, v in resp.items():
        k_omid = f'{omid}.{k}'
        if type(v) == dict:
            # Descend into dict.
            for dk, dv in v.items():
                update_om_metrics(dv, k_omid, labels + [dk], meta_db, om_metrics);
        elif k_omid in om_metrics:
            # Update known metrics.
            dbg(f'updating {k_omid} {labels} to {v}')
            if len(labels):
                om_metrics[k_omid].labels(*labels).set(v)
            else:
                om_metrics[k_omid].set(v)
        else:
            dbg(f'skpping {k_omid}')

def connect_and_monitor(args):
    # Connect to the stats server.
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(args.path)
    f = sock.makefile(mode='rw')

    # Query metadata and build meta_db.
    meta_db = {}
    resp = request(f, 'stats_meta')

    top_sname = None
    for sname, struct in resp.items():
        # Find the top-level struct.
        if 'top' in struct:
            top_sname = sname

        struct['_om_prefix'] = ''
        struct['_om_label'] = ''

        if 'user' in struct:
            # _om_prefix is used to build unique metric name from field names.
            if '_om_prefix' in struct['user']:
                struct['_om_prefix'] = struct['user']['_om_prefix']
            # _om_label is used to distinguish structs nested inside dicts.
            if '_om_label' in struct['user']:
                struct['_om_label'] = struct['user']['_om_label']
            del struct['user']

        meta_db[sname] = struct

    if verbose:
        dbg('dumping meta_db:')
        pprint(meta_db)

    if top_sname not in meta_db:
        raise Exception(f'top-level statistics struct not found among {meta_db.keys()}')

    # Instantiate OpenMetrics Gauges.
    registry = CollectorRegistry()
    om_metrics = {}
    for name, field in meta_db[top_sname]['fields'].items():
        om_metrics |= make_om_metrics(top_sname, f'.{name}', field, [], meta_db, registry)

    # Loop and translate stats.
    while True:
        resp = request(f, 'stats')
        if verbose:
            dbg('dumping stats response:')
            pprint(resp)
        update_om_metrics(resp, '', [], meta_db, om_metrics)

        with tempfile.NamedTemporaryFile() as out_file:
            write_to_textfile(out_file.name, registry)
            with open(out_file.name) as in_file:
                sys.stdout.write(in_file.read())
                sys.stdout.flush()

        time.sleep(args.intv)

def main():
    global verbose

    parser = argparse.ArgumentParser(
        prog='scxstats_to_openmetrics',
        description='Read from scx_stats server and output in OpenMetrics format')
    parser.add_argument('-i', '--intv', metavar='SECS', type=float, default='2.0',
                        help='Polling interval (default: %(default)s)')
    parser.add_argument('-v', '--verbose', action='count')
    parser.add_argument('-p', '--path', metavar='PATH', default='/var/run/scx/root/stats',
                        help='UNIX domain socket path to connect to (default: %(default)s)')

    args = parser.parse_args()
    verbose = args.verbose
    last_e = None

    while True:
        try:
            connect_and_monitor(args)
        except Exception as e:
            if verbose or f'{e}' != f'{last_e}':
                info(f'{e}, retrying...')
                last_e = e
            time.sleep(1)

main()
