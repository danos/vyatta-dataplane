#!/usr/bin/env python3
#
# Copyright (c) 2021, SafePoint.  All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import glob
import json
import os
import sqlite3
import time
import traceback
from datetime import datetime

# Check sqlite3 version
if sqlite3.sqlite_version_info[0] * 1000 + sqlite3.sqlite_version_info[1] <= 3024:
    raise RuntimeError('sqlite3>=3.24.0 required')

DB_FILE = '/var/log/flowstat.db'
LOG_DIR = '/var/log'
LOG_FILE = f'{LOG_DIR}/flowstat.log'

QUERY_PERIOD_MAP = {
    300: (5, 10),  # last 5 minute, period 5, group by 10s
    3600: (60, 60),  # last 1 hour, period 60, group by 1m
    86400: (3600, 3600),  # last 1 day, period 3600, group by 1h
}

PERIOD_LIST = sorted(i[0] for i in QUERY_PERIOD_MAP.values())

AGG_TABLE_LIST = [
    {'name': 'grp_flow_src', 'alias': 'src', 'key': 'src_addr'},
    {'name': 'grp_flow_dst', 'alias': 'dst', 'key': 'dst_addr'},
    {'name': 'grp_app_name', 'alias': 'app', 'key': 'app_name'},
    {'name': 'grp_app_proto', 'alias': 'app_proto', 'key': 'app_proto'},
    {'name': 'grp_app_type', 'alias': 'app_type', 'key': 'app_type'},
]

AGG_COMMON_FIELDS = [
    {'name': 'in_bytes', 'op': 'sum'},
    {'name': 'out_bytes', 'op': 'sum'},
]

AGG_TABLE_TPL = '''
{name}_{period} (
    timestamp interger,
    {key} char(32),
    in_bytes integer,
    out_bytes integer,
    if_name char(32),
    primary key (if_name, timestamp, {key})
)
'''

METADATA_TABLE_TPL = '''
metadata (
    id integer primary key autoincrement,
    data text
)
'''

TEMPFLOW_TABLE_COLS = '''
    timestamp integer,
    session_id integer,
    src_addr char(16),
    src_port integer,
    dst_addr char(16),
    dst_port integer,
    in_bytes integer,
    in_pkts integer,
    protocol integer,
    out_bytes integer,
    out_pkts integer,
    app_name char(32),
    app_proto char(32),
    app_type char(32),
    if_name char(32)
'''

TEMPFLOW_TABLE_TPL = f'''
tempflow (
    id integer primary key autoincrement,
    {TEMPFLOW_TABLE_COLS}
)
'''


class FlowStatDb:
    def __init__(self, dbpath, read_limit=10000, insert_batch=1000):
        self.dbpath = dbpath
        self.temp_read_limit = read_limit
        self.temp_insert_batch = insert_batch
        self.metadata = {
            'last_log': {
                'index': -1,
                'position': 0,
                'timestamp': 0,
            },
        }
        self.conn = None

    @property
    def last_log(self):
        return self.metadata['last_log']

    def connect(self):
        conn = sqlite3.connect(self.dbpath)
        # print("Opened database %s successfully" % file_path)

        sql = ''

        # setup tables
        for period in PERIOD_LIST:
            for table in AGG_TABLE_LIST:
                sql += (f'''
                    create table if not exists {AGG_TABLE_TPL};
                ''').format(**table, period=period)

        # meta data
        sql += f'''
            create table if not exists {METADATA_TABLE_TPL};
        '''

        # temp flow
        sql += f'''
            create temp table if not exists {TEMPFLOW_TABLE_TPL};
        '''

        conn.executescript(sql)

        self.conn = conn

    def close(self):
        self.conn.close()

    def commit(self):
        self.conn.commit()

    def _upsert(self, table, primary_keys, cols, values, cur=None):
        c = cur or self.conn.cursor()
        conflict_cols = ','.join(primary_keys)
        upsert = ','.join(f'{i}=excluded.{i}' for i in cols if i not in primary_keys)
        values_wc = ','.join('?' * len(cols))
        cols = ','.join(cols)
        sql = f'''
            insert into {table} ({cols}) values ({values_wc})
            on conflict ({conflict_cols})
            do update set {upsert}
        '''
        # print(sql)
        c.executemany(sql, values)

        if cur is None:
            c.close()

    def _read_logfile(self, logfile, index, limit, period, last_log):
        line_number = 0
        last_ts = None
        need_reading = True
        changed_ts = False
        while need_reading and index >= 0:
            if index == 0:
                curfile = logfile
            else:
                curfile = '%s.%d' % (logfile, index)

            if not os.path.isfile(curfile):
                index -= 1
                continue

            with open(curfile, 'r') as f:
                # seek first file only
                if index == last_log['index']:
                    f.seek(last_log['position'])

                while True:
                    prev_pos = f.tell()
                    line = f.readline()
                    line_number += 1

                    if line == '':
                        # EOL, go to next file
                        index -= 1
                        break

                    # parse log
                    d = [i.split('=') for i in line.strip().split(' ')]
                    d = {i[0]: (i[1] if len(i) == 2 else None) for i in d}

                    # fix string val
                    for k in ['if_name']:
                        v = d.get(k)
                        if v:
                            d[k] = v[1:len(v) - 1]

                    # save last position
                    ts = int(d['timestamp'])
                    ts = ts - (ts % period)
                    if last_ts is None:
                        last_ts = ts
                        # save timestamp for first line
                        last_log['timestamp'] = int(d['timestamp'])

                    # jump to new timestamp period
                    if ts > last_ts:
                        last_ts = ts
                        last_log['index'] = index
                        last_log['position'] = prev_pos
                        last_log['timestamp'] = int(d['timestamp'])

                    yield d

                    # only break if move over one period
                    if line_number >= limit:
                        if changed_ts:
                            print(f'Read limited line:{line_number}')
                            need_reading = False
                            break
                        elif line_number % limit == 0:
                            time.sleep(1)

    def prepare_temp_data(self, data):
        c = self.conn.cursor()

        cols = [i.split()[0] for i in TEMPFLOW_TABLE_COLS.split(',')]
        values_wc = ','.join('?' * len(cols))
        cols_name = ','.join(cols)

        to_inserts = []
        for d in data:
            to_inserts.append(d)

            # batch insert
            if len(to_inserts) >= self.temp_insert_batch:
                sql = f'''
                    insert into tempflow
                        ({cols_name})
                    values ({values_wc})
                '''
                data_insert = [[d[i] for i in cols] for d in to_inserts]
                c.executemany(sql, data_insert)
                # print('Inserted %d items' % len(to_inserts))
                to_inserts = []

        # remain
        if len(to_inserts):
            sql = f'''
                insert into tempflow
                    ({cols_name})
                values ({values_wc})
            '''
            data_insert = [[d[i] for i in cols] for d in to_inserts]
            c.executemany(sql, data_insert)
            # print('Inserted %d items' % len(to_inserts))

        c.close()

    def _compute_statistics(self):
        c = self.conn.cursor()

        for table in AGG_TABLE_LIST:
            for period in PERIOD_LIST:
                tbname = f'{table["name"]}_{period}'

                # find last time of package
                sql = f'''
                    select timestamp
                    from {tbname}
                    order by timestamp desc
                    limit 1;
                '''
                c.execute(sql)
                last_time = c.fetchone()
                if last_time:
                    where = f'timestamp >= {last_time[0]}'
                else:
                    where = '1=1'

                # each period depends on prev periods
                index = PERIOD_LIST.index(period)
                if index == 0:
                    prev_table = 'tempflow'
                else:
                    prev_period = PERIOD_LIST[index - 1]
                    prev_table = f'{table["name"]}_{prev_period}'

                select = ','.join(f'{i["op"]}({i["name"]})' if 'op' in i else i['name']
                                  for i in AGG_COMMON_FIELDS)
                sql = f'''
                    select if_name, (timestamp - (timestamp % {period})) ts,
                        {table['key']},
                        {select}
                    from {prev_table}
                    where {where}
                    group by if_name,ts,{table['key']}
                '''

                # print(sql)
                c.execute(sql)
                records = c.fetchall()
                # print(records)
                # print(f'Found new {tbname} {len(records)} items')

                # insert into table
                primary_keys = ['if_name', 'timestamp', table['key']]
                extra_cols = [i['name'] for i in AGG_COMMON_FIELDS]
                cols = primary_keys + extra_cols
                self._upsert(tbname, primary_keys, cols, records, cur=c)
                print(f'Updated {tbname} {c.rowcount} items')
        c.close()

    def _check_logfile(self, logfile, index, position, timestamp):
        # find prev file by index
        if index == 0:
            curfile = logfile
        else:
            curfile = '%s.%d' % (logfile, index)

        try:
            with open(curfile, 'r') as f:
                f.seek(position)
                line = f.readline()
                ts = 'timestamp=%d' % timestamp
                return ts in line
        except Exception:
            return False

    def _find_last_logfile(self, logfile, last_log):
        default = {
            'index': 0,
            'position': 0,
            'timestamp': 0,
        }

        if last_log['index'] == -1:
            # no prev info found, load from current file
            return default

        # check last index
        if self._check_logfile(logfile, last_log['index'],
                               last_log['position'],
                               last_log['timestamp']):
            return last_log
        else:
            # last file not valid, check all log
            files = glob.glob(f'{logfile}*')
            for file in sorted(files):
                # extract index from file name
                if file == logfile:
                    index = 0
                else:
                    index = int(file.rsplit('.', 1)[-1])  # log.1,...

                if self._check_logfile(logfile, index, last_log['position'],
                                       last_log['timestamp']):
                    last_log['index'] = index
                    return last_log
            else:
                # nothing found
                return default

    def find_last_logfile(self, logfile):
        last_log = self._find_last_logfile(logfile, self.last_log)
        self.last_log.update(last_log)

    def _load_metadata(self):
        c = self.conn.cursor()
        sql = f'''
            select data
            from metadata
        '''
        c.execute(sql)
        rec = c.fetchone()
        print(f'read lastlog: {rec}')
        if rec:
            data = json.loads(rec[0])
            self.metadata.update(data)
        c.close()

    def _save_metadata(self):
        print(f'save lastlog: {self.last_log}')
        c = self.conn.cursor()
        upsert_cols = [
            'id',
            'data',
        ]
        value = [
            1,
            json.dumps(self.metadata),
        ]
        self._upsert('metadata', ['id'], upsert_cols, [value], cur=c)

        c.close()

    def collect_from_logfile(self, logfile):
        self._load_metadata()
        self.find_last_logfile(logfile)
        data = self._read_logfile(logfile, self.last_log['index'],
                                  self.temp_read_limit, PERIOD_LIST[0], self.last_log)
        self.prepare_temp_data(data)
        self._compute_statistics()
        self._save_metadata()

    def _guess_period(self, start_time, end_time):
        diff = end_time - start_time
        for k, v in QUERY_PERIOD_MAP.items():
            if diff <= k:
                return v
        return 3600, 3600  # default

    def _format_as_json(self, result, fields):
        result = [dict(zip(fields, i)) for i in result]
        return result

    def _find_table(self, alias):
        table = (i for i in AGG_TABLE_LIST if i['alias'] == alias)
        table = next(table, None)
        if not table:
            raise RuntimeError(f'Table not found for alias:{alias}')
        return table

    def query_top(self, alias, attr, start_time, end_time, if_name=None, limit=10):
        table = self._find_table(alias)

        if start_time == 'now':
            table_name = 'tempflow'
            where = '1=1'
        else:
            period, subperiod = self._guess_period(start_time, end_time)
            table_name = f'{table["name"]}_{period}'
            where = f'timestamp between {start_time} and {end_time}'

        if if_name:
            where += f' and if_name = "{if_name}"'

        c = self.conn.cursor()
        sql = f'''
            select {table['key']},
                sum(in_bytes) in_bytes,
                sum(out_bytes) out_bytes,
                sum(in_bytes + out_bytes) bytes
            from {table_name}
            where {where}
            group by {table['key']}
            order by {attr} desc
            limit {limit}
        '''
        # print(sql)
        c.execute(sql)
        res = c.fetchall()
        c.close()
        res = self._format_as_json(res, ['key', 'in_bytes', 'out_bytes', 'bytes'])
        return res

    def query_time_series(self, alias, start_time, end_time, if_name=None):
        period, subperiod = self._guess_period(start_time, end_time)
        table = self._find_table(alias)
        c = self.conn.cursor()

        where = f'timestamp between {start_time} and {end_time}'
        if if_name:
            where += f' and if_name = "{if_name}"'

        sql = f'''
            select timestamp-(timestamp%{subperiod}) ts,
                sum(in_bytes),
                sum(out_bytes),
                sum(in_bytes + out_bytes)
            from {table['name']}_{period}
            where {where}
            group by ts
            order by timestamp asc
        '''
        # print(sql)
        c.execute(sql)
        res = c.fetchall()
        c.close()
        res = self._format_as_json(res, ['timestamp', 'in_bytes', 'out_bytes', 'bytes'])
        return res

    def vacuum(self):
        c = self.conn.cursor()
        m = {v[0]: k for k, v in QUERY_PERIOD_MAP.items()}
        for table in AGG_TABLE_LIST:
            for period in PERIOD_LIST:
                time_diff = m[period]
                tsnow = int(datetime.utcnow().timestamp())
                start = tsnow - (tsnow % period) - time_diff * 2

                # Period is list depend, sub period can not delete item if parent
                # still need them.
                next_index = PERIOD_LIST.index(period) + 1
                if next_index < len(PERIOD_LIST):
                    next_period = PERIOD_LIST[next_index]
                    sql = f'''
                    select timestamp from {table['name']}_{next_period}
                    order by timestamp desc
                    limit 1
                    '''
                    c.execute(sql)
                    res = c.fetchone()
                    if res:
                        start = min(start, res[0])

                # delete
                sql = f'''
                    delete from {table['name']}_{period}
                    where timestamp < {start}
                '''
                # print(sql)
                c.execute(sql)
                if c.rowcount:
                    print(f'Deleted from {table["name"]}_{period} {c.rowcount} items')

        c.close()

    def show_info(self):
        c = self.conn.cursor()

        for table in AGG_TABLE_LIST:
            for period in PERIOD_LIST:
                table_name = f'{table["name"]}_{period}'
                sql = f'''
                    select timestamp
                    from {table_name}
                    order by timestamp asc
                    limit 1
                '''
                c.execute(sql)
                start = c.fetchone()
                if start:
                    start = start[0]
                else:
                    start = '-'

                sql = f'''
                    select timestamp
                    from {table_name}
                    order by timestamp desc
                    limit 1
                '''
                c.execute(sql)
                end = c.fetchone()
                if end:
                    end = end[0]
                else:
                    end = '-'

                sql = f'select count(*) from {table["name"]}_{period}'
                c.execute(sql)
                count = c.fetchone()
                if count:
                    count = count[0]
                else:
                    count = 0

                print(f'{table_name:<20} ({count:08}) {start:>10} => {end:>10}')

        c.close()


def collect_statistics(db_file, log_file):
    st = time.time()

    db = FlowStatDb(db_file)
    db.connect()
    db.collect_from_logfile(log_file)
    db.vacuum()
    # db.show_info()
    db.commit()
    db.close()

    print('Collect finished in %.2fs' % (time.time() - st))


def run_collect():
    while True:
        try:
            collect_statistics(DB_FILE, LOG_FILE)
        except Exception as e:
            traceback.print_exc()
        time.sleep(10)


if __name__ == '__main__':
    run_collect()
