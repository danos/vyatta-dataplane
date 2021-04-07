#!/usr/bin/env python3
#
# Copyright (c) 2021, SafePoint.  All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import argparse
import json
import vplaned

from datetime import datetime
from flowstatd import FlowStatDb

DB_PATH = '/var/log/flowstat.db'

PERIOD_MAP = {
    'now': 0,
    '5m': 300,
    '1h': 3600,
    '1d': 86400,
}

SESSION_STATE_TERMINATING = 3


def _parse_sessions(data):
    ss = data['config']['sessions']

    result = []
    for sid, s in ss.items():
        features = s['features'] or [{}]
        dpi_engines = features[0].get('dpi', {}).get('engines', [])
        dpi = dpi_engines[0] if dpi_engines else {}
        if dpi.get('gen_state') == SESSION_STATE_TERMINATING:
            continue
        d = {
            'timestamp': None,
            'session_id': sid,
            'src_addr': s['src_addr'],
            'src_port': s['src_port'],
            'dst_addr': s['dst_addr'],
            'dst_port': s['dst_port'],
            'in_bytes': s['counters']['bytes_in'],
            'in_pkts': s['counters']['packets_in'],
            'protocol': s['proto'],
            'out_bytes': s['counters']['bytes_out'],
            'out_pkts': s['counters']['packets_out'],
            'if_name': s['interface'],
            'app_name': dpi.get('app-name', ''),
            'app_proto': dpi.get('proto-name', ''),
            'app_type': dpi.get('type', ''),
        }
        result.append(d)

    return result


def _get_sessions():
    cmd = "session-op show sessions full"

    with vplaned.Controller() as controller:
        for dp in controller.get_dataplanes():
            with dp:
                rv = dp.json_command(cmd)
                rv = _parse_sessions(rv)
                return rv


def _output(items):
    """Make sort by yang."""
    res = {
        'items': items
    }

    print(json.dumps(res))


def get_top(key, sort_by, start_time, end_time, if_name=None, limit=10):
    if start_time == 'now':
        db = FlowStatDb(':memory:')
        db.connect()
        data = _get_sessions()
        db.prepare_temp_data(data)
    else:
        db = FlowStatDb(DB_PATH)
        db.connect()

    res = db.query_top(key, sort_by, start_time, end_time, if_name=if_name, limit=limit)
    _output(res)
    db.close()


def get_timeseries(key, start_time, end_time, if_name=None):
    db = FlowStatDb(DB_PATH)
    db.connect()
    res = db.query_time_series(key, start_time, end_time, if_name=if_name)
    _output(res)
    db.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Flowstat query')
    parser.add_argument('--intf', help='Interface')
    parser.add_argument('--type', help='Query type',
                        choices=['top', 'timeseries'], required=True)
    parser.add_argument('--key', help='Key', required=True)
    parser.add_argument('--unit', help='Unit')
    parser.add_argument('--period', help='Period',
                        choices=PERIOD_MAP.keys(), required=True)
    args = parser.parse_args()

    # get start time, end time
    if args.period == 'now':
        start = end = 'now'

        if args.type == 'timeseries':
            _output([])
            exit(0)
    else:
        end = int(datetime.utcnow().timestamp())
        start = end - PERIOD_MAP[args.period]

    # fix ALL interfaces
    if args.intf == 'ALL':
        args.intf = None

    if args.type == 'top':
        get_top(args.key, args.unit, start, end, if_name=args.intf)
        exit(0)

    if args.type == 'timeseries':
        get_timeseries(args.key, start, end, if_name=args.intf)
        exit(0)
