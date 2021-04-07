#!/usr/bin/env python3
#
# Copyright (c) 2021, SafePoint.  All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import os
import unittest
from flowstatd import FlowStatDb

_base_dir = os.path.abspath(__file__ + '/../')


def _abs_path(path):
    return os.path.abspath(os.path.join(_base_dir, path))


def test_query_top_src():
    db = FlowStatDb(':memory:')
    db.connect()
    db.collect_from_logfile(_abs_path('data/2.log'))

    res = db.query_top('src', 'bytes', 1615434285, 1615434288)
    assert len(res) == 2
    item = res[0]
    assert item['key'] == '192.168.100.214'
    assert item['in_bytes'] == 953
    assert item['out_bytes'] == 619
    assert item['bytes'] == 1572

    db.close()


def test_query_timeseries():
    db = FlowStatDb(':memory:')
    db.connect()
    db.collect_from_logfile(_abs_path('data/2.log'))

    res = db.query_time_series('src', 1615434285, 1615434288)
    assert len(res) == 1
    item = res[0]
    assert item['timestamp'] == 1615434280
    assert item['in_bytes'] == 1981
    assert item['out_bytes'] == 922
    assert item['bytes'] == 2903

    db.close()


def test_query_top_src_intf():
    db = FlowStatDb(':memory:')
    db.connect()
    db.collect_from_logfile(_abs_path('data/logintf.log'))

    res = db.query_top('src', 'bytes', 1615434285, 1615434288, if_name='dp0p33p1')
    assert len(res) == 1
    item = res[0]
    assert item['key'] == '192.168.100.79'
    assert item['in_bytes'] == 1028
    assert item['out_bytes'] == 303
    assert item['bytes'] == 1331

    db.close()


def test_query_timeseries_intf():
    db = FlowStatDb(':memory:')
    db.connect()
    db.collect_from_logfile(_abs_path('data/logintf.log'))

    res = db.query_time_series('src', 1615434285, 1615434288, if_name='dp0p33p1')
    assert len(res) == 1
    item = res[0]
    assert item['timestamp'] == 1615434280
    assert item['in_bytes'] == 1028
    assert item['out_bytes'] == 303
    assert item['bytes'] == 1331

    db.close()


def test_read_limit():
    db = FlowStatDb(':memory:', read_limit=1)
    db.connect()

    # read
    db.collect_from_logfile(_abs_path('data/2.log'))

    assert db.last_log['index'] == 0
    assert db.last_log['position'] == 0
    assert db.last_log['timestamp'] == 1615434287

    db.close()


def test_read_limit_2():
    db = FlowStatDb(':memory:', read_limit=1)
    db.connect()

    # read
    db.collect_from_logfile(_abs_path('data/readlimit.log'))

    assert db.last_log['index'] == 0
    assert db.last_log['position'] == 271
    assert db.last_log['timestamp'] == 1615434290

    db.close()


def test_last_logfile():
    db = FlowStatDb(':memory:')
    db.connect()

    # read
    db.collect_from_logfile(_abs_path('data/lastfile.log'))

    assert db.last_log['index'] == 0
    assert db.last_log['position'] == 0
    assert db.last_log['timestamp'] == 1615434287

    db.close()


def test_last_log_again():
    db = FlowStatDb(':memory:')
    db.connect()

    # read 2 times
    db.collect_from_logfile(_abs_path('data/lastfile.log'))
    db.collect_from_logfile(_abs_path('data/lastfile.log'))

    assert db.last_log['index'] == 0
    assert db.last_log['position'] == 0
    assert db.last_log['timestamp'] == 1615434287

    db.close()


def test_last_logfile_position():
    db = FlowStatDb(':memory:')
    db.connect()

    # read
    db.collect_from_logfile(_abs_path('data/lastfile2.log'))

    assert db.last_log['index'] == 0
    assert db.last_log['position'] == 271
    assert db.last_log['timestamp'] == 1615434290

    db.close()


def test_find_last_logfile():
    db = FlowStatDb(':memory:')
    db.connect()

    db._load_metadata()
    db.last_log['index'] = 0
    db.last_log['position'] = 0
    db.last_log['timestamp'] = 1615434287
    db._save_metadata()

    db.find_last_logfile(_abs_path('data/lastfile.log'))

    assert db.last_log['index'] == 0
    assert db.last_log['position'] == 0
    assert db.last_log['timestamp'] == 1615434287

    db.close()


def test_find_last_logfile_rotate():
    db = FlowStatDb(':memory:')
    db.connect()

    # info of old log file
    db.last_log['index'] = 0
    db.last_log['position'] = 0
    db.last_log['timestamp'] = 1615434287
    db._save_metadata()

    db.find_last_logfile(_abs_path('data/rotate.log'))

    assert db.last_log['index'] == 1
    assert db.last_log['position'] == 0
    assert db.last_log['timestamp'] == 1615434287

    db.close()


def test_find_last_logfile_wrong_index():
    db = FlowStatDb(':memory:')
    db.connect()

    db.last_log['index'] = 1
    db.last_log['position'] = 0
    db.last_log['timestamp'] = 1615434287
    db._save_metadata()

    db.find_last_logfile(_abs_path('data/lastfile.log'))

    assert db.last_log['index'] == 0
    assert db.last_log['position'] == 0
    assert db.last_log['timestamp'] == 1615434287

    db.close()


def test_find_last_logfile_wrong_index_timestamp():
    db = FlowStatDb(':memory:')
    db.connect()

    db.last_log['index'] = 1
    db.last_log['position'] = 0
    db.last_log['timestamp'] = 9999
    db._save_metadata()

    db.find_last_logfile(_abs_path('data/lastfile.log'))

    assert db.last_log['index'] == 0
    assert db.last_log['position'] == 0
    assert db.last_log['timestamp'] == 0

    db.close()


def test_find_last_logfile_wrong_position():
    db = FlowStatDb(':memory:')
    db.connect()

    db.last_log['index'] = 0
    db.last_log['position'] = 9999
    db.last_log['timestamp'] = 1615434287
    db._save_metadata()

    db.find_last_logfile(_abs_path('data/lastfile.log'))

    assert db.last_log['index'] == 0
    assert db.last_log['position'] == 0
    assert db.last_log['timestamp'] == 0

    db.close()


def test_find_last_logfile_wrong_timestamp():
    db = FlowStatDb(':memory:')
    db.connect()

    db.last_log['index'] = 0
    db.last_log['position'] = 0
    db.last_log['timestamp'] = 9999
    db._save_metadata()

    db.find_last_logfile(_abs_path('data/lastfile.log'))

    assert db.last_log['index'] == 0
    assert db.last_log['position'] == 0
    assert db.last_log['timestamp'] == 0

    db.close()


def test_read_two_rotate_logfile_jump_next():
    db = FlowStatDb(':memory:')
    db.connect()

    # info of old log file
    db.last_log['index'] = 0
    db.last_log['position'] = 0
    db.last_log['timestamp'] = 1615434287
    db._save_metadata()

    # read next
    db.collect_from_logfile(_abs_path('data/rotate.log'))

    assert db.last_log['index'] == 0
    assert db.last_log['position'] == 0
    assert db.last_log['timestamp'] == 1615434290

    db.close()


def test_read_two_rotate_logfile_not_jump():
    db = FlowStatDb(':memory:')
    db.connect()

    # info of old log file
    db.last_log['index'] = 0
    db.last_log['position'] = 0
    db.last_log['timestamp'] = 1615434287
    db._save_metadata()

    # read new
    db.collect_from_logfile(_abs_path('data/rotate2.log'))

    assert db.last_log['index'] == 1
    assert db.last_log['position'] == 0
    assert db.last_log['timestamp'] == 1615434287

    db.close()


if __name__ == '__main__':
    unittest.main()
