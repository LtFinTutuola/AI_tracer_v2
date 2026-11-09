"""Read-only, repeatable integrity check of a qualified catalog against its input."""
import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3


def connect(path):
    return sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)


def digest(connection, table, ignore_flags=False):
    # Names originate only in SQLite metadata, never in supplied SQL.
    quote = lambda value: '"' + value.replace('"', '""') + '"'
    columns = [row[1] for row in connection.execute('PRAGMA table_info(' + quote(table) + ')')
               if not (ignore_flags and row[1] == 'to_trace')]
    sql = 'SELECT ' + ','.join(map(quote, columns)) + ' FROM ' + quote(table) + ' ORDER BY ' + ','.join(map(quote, columns))
    value, count = hashlib.sha256(), 0
    for row in connection.execute(sql):
        value.update(json.dumps(row, separators=(',', ':'), ensure_ascii=True).encode('utf-8'))
        value.update(b'\n')
        count += 1
    return count, value.hexdigest()


def verify(source, qualified, repeat=None):
    with closing(connect(source)) as original, closing(connect(qualified)) as selected:
        assert selected.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert selected.execute('PRAGMA foreign_key_check').fetchall() == []
        tables = [row[0] for row in original.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                  if row[0] != 'analysis_manifest' and not row[0].startswith(('trace_selection_', 'trace_interest_'))]
        checks = {}
        for table in tables:
            before, after = digest(original, table, table == 'basic_blocks'), digest(selected, table, table == 'basic_blocks')
            assert before == after, 'Changed immutable table: ' + table
            checks[table] = {'rows': before[0], 'sha256': before[1]}
        mismatches = selected.execute('''SELECT count(*) FROM basic_blocks b LEFT JOIN trace_selection_decisions d
            ON d.legacy_id=b.id WHERE d.legacy_id IS NULL OR d.enabled<>b.to_trace''').fetchone()[0]
        assert mismatches == 0
        profile = selected.execute('SELECT status,input_fingerprint,metrics_json FROM trace_selection_profiles').fetchone()
        assert profile and profile[1] == dict(original.execute('SELECT key,value FROM analysis_manifest'))['fingerprint']
        if profile[0] == 'fallback':
            assert digest(original, 'basic_blocks') == digest(selected, 'basic_blocks'), 'Fallback changed baseline flags'
        report = {'immutable_tables': checks, 'flags_match_decisions': True, 'profile_status': profile[0],
                  'integrity': 'ok', 'selection': json.loads(profile[2])}
        if repeat:
            with closing(connect(repeat)) as repeated:
                current_id = selected.execute('SELECT id FROM trace_selection_profiles').fetchone()[0]
                assert current_id == repeated.execute('SELECT id FROM trace_selection_profiles').fetchone()[0]
                repeat_checks = {}
                for table in ('basic_blocks', 'trace_selection_decisions', 'trace_selection_roots', 'trace_interest_evidence'):
                    before, after = digest(repeated, table), digest(selected, table)
                    assert before == after, 'Nondeterministic selection table: ' + table
                    repeat_checks[table] = {'rows': after[0], 'sha256': after[1]}
                report['reproducibility'] = {'profile_id': current_id, 'tables': repeat_checks, 'matched': True}
        return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source')
    parser.add_argument('qualified')
    parser.add_argument('report')
    parser.add_argument('--repeat', help='Another output from identical inputs/options/rules')
    args = parser.parse_args()
    report = verify(args.source, args.qualified, args.repeat)
    Path(args.report).write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'verified_tables': len(report['immutable_tables']), 'integrity': report['integrity'],
                      'profile_status': report['profile_status']}))
