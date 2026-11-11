import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from context_reader import BlockContextReader
from static_flow_decoder import StaticFlowDecoder
from main import build_command, selection_options


class StaticFlowDecoderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self.tmp.name)
        self.db = self.folder / 'static.sqlite'
        with closing(sqlite3.connect(self.db)) as c:
            c.executescript('''
                CREATE TABLE analysis_manifest(key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE methods(id INTEGER PRIMARY KEY,variant_id INTEGER,signature TEXT);
                CREATE TABLE legacy_block_links(legacy_id INTEGER,method_id INTEGER);
                CREATE TABLE application_probe_bindings(legacy_id INTEGER,observation_id TEXT);
                CREATE TABLE application_observations(id TEXT,method_id INTEGER);
                CREATE TABLE static_flow_decisions(probe_id INTEGER,enabled INTEGER,reason TEXT,evidence TEXT);
                CREATE TABLE static_flow_methods(method_id INTEGER,status TEXT,evidence TEXT);
                CREATE TABLE static_flow_languages(method_id INTEGER,first_probe INTEGER,word_json TEXT);
                INSERT INTO methods VALUES(1,1,'A'),(2,1,'B');
                INSERT INTO legacy_block_links VALUES(10,1),(20,2),(30,1);
                INSERT INTO static_flow_decisions VALUES(10,1,'retained',''),(20,1,'retained',''),(30,0,'suppressed_by_repeat_policy','');
                INSERT INTO static_flow_methods VALUES(1,'qualified_abstraction','');
                INSERT INTO static_flow_languages VALUES(1,10,'[10,20]');
            ''')
            c.executemany('INSERT INTO analysis_manifest VALUES(?,?)', {
                'schema_version': '8', 'state': 'validated', 'injection_contract': 'static_probes_v1',
                'selection_profile_id': 'profile', 'fingerprint': 'inputs', 'application_policy_fingerprint': 'policy',
                'static_flow_summary': json.dumps({'losses': ['internal repetition omitted']})}.items())
            c.commit()
        self.reader = BlockContextReader(self.db)

    def tearDown(self):
        self.reader.close()
        self.tmp.cleanup()

    def decode(self, rows, **kwargs):
        log = self.folder / 'trace.log'
        log.write_text('\n'.join(rows) + '\n', encoding='utf-8')
        return list(StaticFlowDecoder(self.reader, allow_unverified=True, **kwargs).decode(log))

    def line(self, probe, thread=1):
        return f'2026-11-11T10:00:00Z||trace||{thread}||{probe}'

    def test_static_configuration_and_no_depth_dependency(self):
        options = selection_options({'mode': 'static', 'ambiguity_budget': 0, 'max_call_depth': 0})
        self.assertEqual(options['repeat_policy'], 'boundaries')
        command = build_command({'target_solution': 'app.sln', 'target_framework': 'net8.0', 'working_folder': 'static',
                                 'trace_selection': {'mode': 'static', 'ambiguity_budget': 0}}, ROOT)
        self.assertIn('--repeat-policy', command)
        self.assertIn('--selection-max-flow-states', command)
        for value in [{'mode': 'static'}, {'mode': 'static', 'ambiguity_budget': 0, 'repeat_policy': 'sample'},
                      {'mode': 'static', 'ambiguity_budget': 0, 'max_flow_states': 0}]:
            with self.assertRaises(ValueError):
                selection_options(value)

    def test_matching_retains_events_without_inventing_iteration_counts(self):
        records = self.decode([self.line(10), self.line(20)])
        segment = records[0]
        self.assertEqual(segment['matching_methods'], [1])
        self.assertEqual([e['probe_id'] for e in segment['observations']], [10, 20])
        self.assertIsNone(segment['iteration_count'])
        self.assertIsNone(segment['recursion_depth'])
        self.assertFalse(segment['closed'])
        self.assertNotEqual(segment['status'], 'unique')
        self.assertTrue(segment['losses'])

    def test_threads_are_never_joined(self):
        records = self.decode([self.line(10, 1), self.line(20, 2)])
        self.assertEqual(len([r for r in records if r['kind'] == 'static_segment']), 2)
        self.assertFalse(any(r.get('matching_methods') for r in records))

    def test_malformed_gap_unknown_and_disabled_preserve_raw_events(self):
        records = self.decode([self.line(10), 'invalid', self.line(30), self.line(999)])
        self.assertEqual([e['probe_id'] for r in records for e in r.get('observations', [])], [10, 30, 999])
        self.assertTrue(any(r['kind'] == 'gap' for r in records))
        self.assertEqual(records[-1]['events_read'], 3)

    def test_budget_preserves_each_marker(self):
        records = self.decode([self.line(10), self.line(20)] * 100, max_states=1)
        self.assertEqual(sum(len(r.get('observations', [])) for r in records), 200)

    def test_manifest_mismatch_fails_before_decoding(self):
        manifest = self.folder / 'build.json'
        manifest.write_text(json.dumps({'schema_version': 8, 'injection_contract': 'static_probes_v1',
                            'profile_id': 'wrong', 'input_fingerprint': 'inputs', 'policy_fingerprint': 'policy'}))
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            StaticFlowDecoder(self.reader, manifest)

    def test_truncated_word_is_incomplete(self):
        records = self.decode([self.line(10)])
        self.assertEqual(records[0]['status'], 'incomplete')
        self.assertTrue(records[0]['longer_candidates_remain'])


class CompiledStaticFlowTests(unittest.TestCase):
    def test_compiled_fixture_matches_and_renders(self):
        folder = Path(os.environ.get('STATIC_FLOW_FIXTURE', ROOT.parent / 'scratch/static-tests-4/static-flow'))
        if not (folder / 'fixture.aitracer.json').exists():
            self.skipTest('Run .NET --static-only first')
        with_reader = BlockContextReader(folder / 'fixture.sqlite')
        try:
            decoder = StaticFlowDecoder(with_reader, folder / 'fixture.aitracer.json')
            records = list(decoder.decode(folder / 'branch-True.log'))
            self.assertEqual(decoder.binding_status, 'verified')
            self.assertTrue(any(r.get('matching_methods') for r in records))
            probe = next(e['probe_id'] for r in records for e in r.get('observations', []))
            context = with_reader.get_block_context(probe)
            self.assertIsNotNone(context['static_flow_decision'])
            self.assertIsNotNone(context['trace_selection'])
            self.assertTrue(context['methods'])
            from generate_map import main
            with tempfile.TemporaryDirectory() as temp:
                output = Path(temp) / 'map.md'
                code = main(['--db', str(folder/'fixture.sqlite'), '--log', str(folder/'branch-True.log'),
                             '--build-manifest', str(folder/'fixture.aitracer.json'), '--source-context', '0', '--output', str(output)])
                self.assertEqual(code, 2)
                self.assertIn('profondità ricorsiva non dimostrati', output.read_text(encoding='utf-8'))
                self.assertTrue(output.with_suffix('.jsonl').exists())
        finally:
            with_reader.close()


if __name__ == '__main__':
    unittest.main()
