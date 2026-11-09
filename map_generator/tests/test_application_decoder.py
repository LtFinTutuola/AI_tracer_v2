import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from context_reader import BlockContextReader
from application_decoder import ApplicationDecoder
from main import build_command, selection_options


class ApplicationDecoderTests(unittest.TestCase):
    @contextmanager
    def connection(self):
        c = sqlite3.connect(self.db)
        try:
            with c:
                yield c
        finally:
            c.close()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.db = self.folder / 'catalog.sqlite'
        with self.connection() as c:
            c.executescript('''
              CREATE TABLE analysis_manifest(key TEXT PRIMARY KEY,value TEXT);
              INSERT INTO analysis_manifest VALUES('schema_version','6'),('state','validated'),
                ('injection_contract','application_edits_v1'),('selection_profile_id','profile'),
                ('application_policy_fingerprint','policy'),('fingerprint','inputs');
              CREATE TABLE methods(id INTEGER PRIMARY KEY,signature TEXT);
              INSERT INTO methods VALUES(1,'A'),(2,'B');
              CREATE TABLE application_method_facts(method_id INTEGER,is_async INTEGER);
              INSERT INTO application_method_facts VALUES(1,0),(2,0);
              CREATE TABLE basic_blocks(id INTEGER PRIMARY KEY,to_trace INTEGER);
              INSERT INTO basic_blocks VALUES(1,1),(2,1),(3,1),(4,1);
              CREATE TABLE application_observations(id TEXT PRIMARY KEY,method_id INTEGER,variant_id INTEGER,kind TEXT,evidence TEXT,status TEXT);
              INSERT INTO application_observations VALUES('a-enter',1,1,'operation_enter','operation','modeled'),
                ('b-enter',2,1,'operation_enter','operation','modeled'),('b-leave',2,1,'operation_leave','body_left','modeled'),
                ('a-leave',1,1,'operation_leave','body_left','modeled');
              CREATE TABLE application_locations(observation_id TEXT,node_id INTEGER,position INTEGER,edge_id INTEGER);
              INSERT INTO application_locations VALUES('a-enter',10,0,NULL),('b-enter',40,0,NULL),('b-leave',60,0,NULL),('a-leave',30,0,NULL);
              CREATE TABLE application_probe_bindings(observation_id TEXT,legacy_id INTEGER);
              INSERT INTO application_probe_bindings VALUES('a-enter',1),('b-enter',2),('b-leave',3),('a-leave',4);
              CREATE TABLE application_placements(legacy_id INTEGER,anchor INTEGER,path TEXT DEFAULT 'A.cs');
              INSERT INTO application_placements(legacy_id,anchor) VALUES(1,1),(2,2),(3,3),(4,4);
              CREATE TABLE documents(path TEXT,variant_id INTEGER,origin TEXT);
              INSERT INTO documents VALUES('A.cs',1,'source');
              CREATE TABLE project_variants(id INTEGER,name TEXT);
              INSERT INTO project_variants VALUES(1,'one');
              CREATE TABLE flow_nodes(id INTEGER PRIMARY KEY,method_id INTEGER,kind TEXT);
              INSERT INTO flow_nodes VALUES(10,1,'Entry'),(20,1,'Block'),(30,1,'Exit'),(40,2,'Entry'),(50,2,'Block'),(60,2,'Exit');
              CREATE TABLE flow_points(id INTEGER PRIMARY KEY,node_id INTEGER,position INTEGER,kind TEXT);
              INSERT INTO flow_points VALUES(100,10,0,'entry'),(200,20,0,'source_before'),(201,20,1,'call'),
                (300,30,0,'exit'),(400,40,0,'entry'),(500,50,0,'source_before'),(600,60,0,'exit');
              CREATE TABLE flow_edges(id INTEGER PRIMARY KEY,source_id INTEGER,target_id INTEGER,status TEXT);
              INSERT INTO flow_edges VALUES(1,10,20,'modeled'),(2,20,30,'modeled'),(3,40,50,'modeled'),(4,50,60,'modeled');
              CREATE TABLE call_sites(id INTEGER PRIMARY KEY,method_id INTEGER,point_id INTEGER,resolution TEXT,continuation_position INTEGER);
              INSERT INTO call_sites VALUES(1,1,201,'static',2);
              CREATE TABLE call_targets(site_id INTEGER,method_id INTEGER);
              INSERT INTO call_targets VALUES(1,2);
            ''')
        self.manifest = self.folder / 'build.json'
        self.manifest.write_text(json.dumps(dict(schema_version=6, profile_id='profile', policy_fingerprint='policy',
                                                input_fingerprint='inputs', injection_contract='application_edits_v1')))

    def decode(self, words, **limits):
        log = self.folder / 'runtime.log'
        log.write_text('\n'.join(f'2026-11-09T10:00:00Z||{trace}||{thread}||{probe}'
                                 for trace, thread, probe in words) + '\n')
        reader = BlockContextReader(self.db)
        try:
            decoder = ApplicationDecoder(reader, self.manifest, **limits)
            return list(decoder.decode(log))
        finally:
            reader.close()

    def word(self, values, **limits):
        return self.decode([('shared', '1', value) for value in values], **limits)

    def test_balanced_calls_and_silent_points(self):
        result = self.word([1, 2, 3, 4])
        self.assertEqual(result[0]['status'], 'unique')
        self.assertEqual([e['probe_id'] for e in result[0]['observations']], [1, 2, 3, 4])
        self.assertTrue(result[0]['closed'])

    def test_repeated_call_sites_have_distinct_continuations(self):
        with self.connection() as c:
            c.execute("INSERT INTO flow_points VALUES(202,20,2,'call')")
            c.execute("INSERT INTO call_sites VALUES(2,1,202,'static',3)")
            c.execute("INSERT INTO call_targets VALUES(2,2)")
        self.assertEqual(self.word([1, 2, 3, 2, 3, 4])[0]['status'], 'unique')
        self.assertEqual(self.word([1, 2, 3, 4])[0]['status'], 'incomplete')

    def test_wrong_order_not_declared_unique(self):
        self.assertTrue(all(x['status'] != 'unique' for x in self.word([1, 3, 2, 4]) if x['kind'] == 'application_segment'))

    def test_declared_branch_edges(self):
        with self.connection() as c:
            c.executescript('''INSERT INTO basic_blocks VALUES(5,1),(6,1);
              INSERT INTO application_observations VALUES('yes',1,1,'decision','yes','modeled'),('no',1,1,'decision','no','modeled');
              INSERT INTO application_locations VALUES('yes',10,2147483647,1),('no',10,2147483647,5);
              INSERT INTO application_probe_bindings VALUES('yes',5),('no',6);
              INSERT INTO application_placements(legacy_id,anchor) VALUES(5,5),(6,6);
              INSERT INTO flow_edges VALUES(5,10,30,'modeled');''')
        self.assertEqual(self.word([1, 5, 2, 3, 4])[0]['status'], 'unique')
        self.assertEqual(self.word([1, 6, 4])[0]['status'], 'unique')
        self.assertEqual(self.word([1, 6, 2, 3, 4])[0]['status'], 'incomplete')

    def test_threads_not_joined_by_shared_trace_id(self):
        result = self.decode([('same', '1', 1), ('same', '2', 3), ('same', '1', 2)])
        segments = [r for r in result if r['kind'] == 'application_segment']
        self.assertGreaterEqual(len(segments), 2)
        self.assertTrue(all(r['status'] == 'incomplete' for r in segments))

    def test_async_correlation_is_explicit(self):
        with self.connection() as c:
            c.execute('UPDATE application_method_facts SET is_async=1 WHERE method_id=2')
        result = self.word([1, 2, 3, 4])
        self.assertNotEqual(result[0]['status'], 'unique')
        self.assertTrue(any('async' in reason for r in result if r['kind'] == 'application_segment' for reason in r['reasons']))

    def test_unknown_disabled_and_truncated(self):
        result = self.word([1, 999])
        self.assertEqual(result[0]['unexpected_probe_id'], 999)
        self.assertEqual(self.word([1, 2])[0]['status'], 'incomplete')
        with self.connection() as c:
            c.execute('UPDATE basic_blocks SET to_trace=0 WHERE id=2')
        self.assertEqual(self.word([1, 2])[0]['unexpected_probe_id'], 2)

    def test_budget_is_not_no_path_or_unique(self):
        result = self.word([1, 2, 3, 4], max_states=2)
        self.assertTrue(any(r.get('status') == 'budget_exceeded' for r in result))

    def test_compiling_variant_without_binding_is_not_unique(self):
        with self.connection() as c:
            c.execute("INSERT INTO project_variants VALUES(2,'other')")
            c.execute("INSERT INTO documents VALUES('A.cs',2,'source')")
        result=self.word([1,2,3,4])
        self.assertEqual(result[0]['status'],'incomplete')
        self.assertIn('probe_emittable_in_unmapped_variant',result[0]['reasons'])

    def test_silent_cycles_are_not_enumerated(self):
        with self.connection() as c:
            c.execute("INSERT INTO flow_edges VALUES(9,50,50,'modeled')")
        result=self.word([1,2,3,4])
        self.assertEqual(result[0]['status'],'unique')
        self.assertLess(result[-1]['peak_states'],100)

    def test_recursion_obeys_depth_budget(self):
        with self.connection() as c:
            c.execute("INSERT INTO flow_points VALUES(501,50,1,'call')")
            c.execute("INSERT INTO call_sites VALUES(2,2,501,'static',2)")
            c.execute("INSERT INTO call_targets VALUES(2,2)")
        result=self.word([1,2,2,2,2,2],max_depth=2)
        self.assertTrue(any(r.get('status')=='budget_exceeded' for r in result))

    def test_manifest_mismatch_fails_before_reading_log(self):
        self.manifest.write_text(self.manifest.read_text().replace('profile', 'other'))
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            self.word([1, 2, 3, 4])

    def test_read_only_and_no_global_catalog_queries(self):
        reader = BlockContextReader(self.db)
        calls = []
        reader.connection.set_trace_callback(calls.append)
        log = self.folder / 'log'
        log.write_text('2026-11-09T10:00:00Z||x||1||1\n')
        try:
            list(ApplicationDecoder(reader, self.manifest).decode(log))
            self.assertFalse(reader.connection.in_transaction)
            self.assertTrue(all(' WHERE ' in sql.upper() for sql in calls if sql.lstrip().upper().startswith('SELECT')))
        finally:
            reader.close()

    def test_application_config_contract(self):
        profile = ROOT / 'profiles/droidpos.application.json'
        options = dict(mode='application', ambiguity_budget=0, observation_policy=str(profile))
        self.assertEqual(selection_options(options)['mode'], 'application')
        command = build_command(dict(target_solution='x.sln', target_framework='net8.0', working_folder='x', trace_selection=options), ROOT)
        self.assertEqual(command[command.index('--selection-mode') + 1], 'application')
        for bad in [dict(options, ambiguity_budget=.01), dict(options, interest_filter_enabled=True),
                    dict(options, observation_policy=''), dict(options, mode=True)]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                selection_options(bad)


class CompiledApplicationTests(unittest.TestCase):
    def test_shared_variants_are_not_arbitrarily_chosen(self):
        path=Path(os.environ.get('APPLICATION_FIXTURE',ROOT.parent/'artifacts/application-v6-delivery'))
        if not (path/'application-variants.sqlite').exists():
            self.skipTest('Export shared .NET application fixture first')
        reader=BlockContextReader(path/'application-variants.sqlite')
        try:
            result=list(ApplicationDecoder(reader,path/'application-variants.profile.json',max_candidates=1).decode(path/'application-variants.log'))
            segments=[r for r in result if r['kind']=='application_segment']
            self.assertEqual(segments[0]['status'],'ambiguous')
            self.assertTrue(any(e['alternatives_truncated'] for e in segments[0]['observations']))
            self.assertEqual(len(reader.get_application_entries(limit=1)['entries']),1)
        finally:
            reader.close()

    def test_constructor_body_markers_follow_base_initializers(self):
        path=Path(os.environ.get('APPLICATION_FIXTURE',ROOT.parent/'artifacts/application-v6-delivery'))
        if not (path/'application-constructors.log').exists():
            self.skipTest('Export constructor .NET application fixture first')
        reader=BlockContextReader(path/'application.sqlite')
        try:
            result=list(reader.decode_log(path/'application-constructors.log',path/'application.profile.json'))
            signatures=[r['observations'][0]['alternatives'][0]['signature'] for r in result if r['kind']=='application_segment']
            self.assertIn('BaseFixture',signatures[0])
            self.assertIn('ApplicationFixture',signatures[-1])
        finally:
            reader.close()

    def test_real_injected_fixture_is_decodable(self):
        path = Path(os.environ.get('APPLICATION_FIXTURE', ROOT.parent / 'artifacts/application-v6-delivery'))
        if not (path / 'application.sqlite').exists():
            self.skipTest('Export .NET application fixture before integration decoding')
        with_reader = BlockContextReader(path / 'application.sqlite')
        try:
            words = []
            for index in range(3):
                result = list(ApplicationDecoder(with_reader, path / 'application.profile.json').decode(path / f'application-events-{index}.log'))
                words.append([o['probe_id'] for r in result if r['kind'] == 'application_segment' for o in r['observations']])
                self.assertTrue(any(r['kind'] == 'application_segment' and r['closed'] for r in result))
            self.assertEqual(len({tuple(w) for w in words}), 3)
        finally:
            with_reader.close()


if __name__ == '__main__':
    unittest.main()
