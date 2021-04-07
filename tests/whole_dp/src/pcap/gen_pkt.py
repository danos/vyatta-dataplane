#!/usr/bin/env python3
#
# Copyright (c) 2021, SafePoint.  All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import pcapkit


def extract(file):
    src = None
    items = []
    extraction = pcapkit.extract(fin=file, nofile=True)
    for frame in extraction.frame:
        if frame.info.protocols.startswith('Ethernet:IPv4:TCP'):
            ethernet = frame.payload
            ipv4 = ethernet.payload
            tcp = ipv4.payload
            tcp_len = len(tcp.payload.data)

            if src is None:
                src = str(ipv4.src)

            dp_dir = 'DPT_FORW' if str(ipv4.src) == src else 'DPT_BACK'
            c_data = ''.join(f'\\x{i:02x}' for i in tcp.payload.data)
            c_data = f'"{c_data}"' if tcp_len else 'NULL'

            # flags
            m = {
                'urg': 'urg',
                'ack': 'ack',
                'psh': 'push',
                'rst': 'rst',
                'syn': 'syn',
                'fin': 'fin',
            }
            flags = [m[i] for i in list(tcp.info.flags) if getattr(tcp.info.flags, i, False)]
            flags = sorted(flags, key=lambda f: f == 'ack')
            flags = ' | '.join(f'TH_{i}'.upper() for i in flags)

            # fix fin,ack
            if 'TH_FIN' in flags and 'TH_ACK' in flags:
                for f in ['TH_FIN', 'TH_ACK']:
                    val = f'{dp_dir}, {f}, 0, NULL, 0, NULL'
                    items.append(val)
            else:
                val = f'{dp_dir}, {flags}, {tcp_len}, {c_data}, 0, NULL'
                items.append(val)

    name = file.rsplit('.', 1)[0].replace('-', '_')  + '_pkt'
    result = []
    result += [f'/* generated from: {file} */']
    result += ['']
    result += ['#include "dp_test_lib_tcp.h"']
    result += ['']
    result += ['struct dpt_tcp_flow_pkt %s[] = {' % name]
    for i in items:
        result += ['\t{%s},' % i]
    result += ['};']
    result += ['']
    result = '\n'.join(result)
    return result


def _main():
    import argparse

    parser = argparse.ArgumentParser('Flow test generator')
    parser.add_argument('file', help='file.pcap')
    args = parser.parse_args()

    result = extract(args.file)

    out_file = args.file.rsplit('.', 1)[0] + '.h'
    with open(out_file, 'w') as f:
        f.write(result)
    print(f'Wrote to file {out_file}')


if __name__ == '__main__':
    _main()
