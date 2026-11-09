import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from context_reader import BlockContextReader
from main import build_command


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / 'catalog.sqlite'
        with sqlite3.connect(self.path) as db:
            db.executescript('''
              CREATE TABLE analysis_manifest(key TEXT,value TEXT);
              INSERT INTO analysis_manifest VALUES('schema_version','3'),('state','validated');
              CREATE TABLE project_variants(id INTEGER,stable_key TEXT,name TEXT,path TEXT);
              INSERT INTO project_variants VALUES(1,'a','A','A.csproj'),(2,'b','B','B.csproj'),(3,'c','C','C.csproj'),(4,'o','Other','Other.csproj');
              CREATE TABLE documents(id INTEGER,variant_id INTEGER,path TEXT,origin TEXT);
              INSERT INTO documents VALUES(1,1,'A.cs','source'),(2,2,'B.cs','source'),(3,3,'C.cs','source'),(4,4,'Other.cs','source');
              CREATE TABLE methods(id INTEGER,signature TEXT,status TEXT,document_id INTEGER,variant_id INTEGER);
              INSERT INTO methods VALUES(1,'A','analyzed',1,1),(2,'B','analyzed',2,2),(3,'C','analyzed',3,3),(4,'Other','analyzed',4,4);
              CREATE TABLE basic_blocks(id INTEGER,method_signature TEXT,file_path TEXT);
              INSERT INTO basic_blocks VALUES(1,'A return','A.cs'),(2,'C body','C.cs'),(3,'A after calls','A.cs'),(4,'Other body','Other.cs'),(5,'unmapped','A.cs');
              CREATE TABLE legacy_probe_variants(legacy_id INTEGER,variant_id INTEGER);
              INSERT INTO legacy_probe_variants VALUES(1,1),(2,3),(3,1),(4,4),(5,1);
              CREATE TABLE legacy_block_links(legacy_id INTEGER,method_id INTEGER,point_id INTEGER,mapping_kind TEXT);
              INSERT INTO legacy_block_links VALUES(1,1,20,'exact_point'),(2,3,50,'exact_point'),(3,1,33,'exact_point'),(4,4,70,'exact_point'),(5,1,NULL,'unmapped');
              CREATE TABLE flow_nodes(id INTEGER,method_id INTEGER,ordinal INTEGER,kind TEXT);
              INSERT INTO flow_nodes VALUES(1,1,0,'Entry'),(2,1,1,'Block'),(3,1,2,'Block'),(6,1,3,'Exit'),
                 (4,2,0,'Entry'),(8,2,1,'Exit'),(5,3,0,'Entry'),(9,3,1,'Exit'),(7,4,0,'Entry');
              CREATE TABLE flow_points(id INTEGER,node_id INTEGER,position INTEGER,kind TEXT);
              INSERT INTO flow_points VALUES(10,1,0,'entry'),(20,2,0,'legacy'),
                (30,3,0,'boundary'),(31,3,1,'call'),(32,3,2,'call'),(33,3,3,'legacy'),
                (40,4,0,'entry'),(41,4,1,'call'),(50,5,0,'legacy'),(60,6,0,'exit'),
                (70,7,0,'legacy'),(80,8,0,'exit'),(90,9,0,'exit');
              CREATE TABLE flow_edges(id INTEGER,source_id INTEGER,target_id INTEGER,alternative TEXT,semantics TEXT,status TEXT);
              INSERT INTO flow_edges VALUES(1,1,2,'true','Regular','modeled'),(2,1,3,'false','Regular','modeled'),
                (3,2,6,'unconditional','Return','modeled'),(4,3,6,'unconditional','Regular','modeled'),
                (5,4,8,'unconditional','Regular','modeled'),(6,5,9,'unconditional','Regular','modeled');
              CREATE TABLE call_sites(id INTEGER,method_id INTEGER,point_id INTEGER,resolution TEXT,continuation_position INTEGER);
              INSERT INTO call_sites VALUES(1,1,31,'static',2),(2,1,32,'static',3),(3,2,41,'static',2);
              CREATE TABLE call_targets(site_id INTEGER,method_id INTEGER,evidence TEXT);
              INSERT INTO call_targets VALUES(1,2,'declared_target'),(2,2,'declared_target'),(3,3,'declared_target');
              CREATE TABLE analysis_diagnostics(id INTEGER,scope TEXT,code TEXT,message TEXT);
            ''')
        db.close()
        self.reader = BlockContextReader(self.path)

    def tearDown(self):
        self.reader.close()
        self.folder.cleanup()

    def mutate(self, sql):
        self.reader.close()
        with sqlite3.connect(self.path) as db:
            db.executescript(sql)
        db.close()
        self.reader = BlockContextReader(self.path)

    def test_guard_return_does_not_call_b(self):
        result = self.reader.explain_context(1, 1)
        self.assertEqual(result['status'], 'found')
        self.assertFalse(any('call' in e for e in result['witness']))
        self.assertIn('true', [e.get('alternative') for e in result['witness']])

    def test_chain_through_methods_without_legacy_probes(self):
        result = self.reader.explain_context(1, 2)
        self.assertEqual([e['target'] for e in result['witness'] if 'call' in e], [2, 3])
        self.assertFalse(result['model_incomplete'])

    def test_repeated_calls_return_to_correct_continuation(self):
        result = self.reader.explain_context(1, 3)
        events = [(k, e[k]) for e in result['witness'] for k in ('call', 'return') if k in e]
        self.assertEqual(events, [('call', 1), ('call', 3), ('return', 3), ('return', 1),
                                  ('call', 2), ('call', 3), ('return', 3), ('return', 2)])

    def test_no_return_to_unrelated_caller(self):
        self.assertEqual(self.reader.explain_context(1, 4)['status'], 'not_found')

    def test_budget_and_depth(self):
        self.assertEqual(self.reader.explain_context(1, 2, budget=1)['status'], 'budget_exceeded')
        self.assertEqual(self.reader.explain_context(1, 2, max_depth=1)['status'], 'depth_exceeded')

    def test_recursion_and_cycle_are_bounded(self):
        self.mutate("UPDATE call_targets SET method_id=2 WHERE site_id=3; INSERT INTO flow_edges VALUES(7,2,2,'loop','Regular','modeled')")
        self.assertEqual(self.reader.explain_context(1, 4, max_depth=3)['status'], 'depth_exceeded')

    def test_external_return_marks_witness_incomplete(self):
        self.mutate("DELETE FROM call_targets WHERE site_id=1; UPDATE call_sites SET resolution='external' WHERE id=1")
        result = self.reader.explain_context(1, 3)
        self.assertEqual(result['status'], 'found')
        self.assertTrue(result['model_incomplete'])

    def test_open_dispatch_declared_candidate(self):
        self.mutate("UPDATE call_sites SET resolution='dispatch_open' WHERE id=1")
        self.assertTrue(self.reader.explain_context(1, 2)['model_incomplete'])

    def test_semantic_errors_mark_candidate_incomplete(self):
        self.mutate("INSERT INTO analysis_diagnostics VALUES(1,'document:2','SEMANTIC_ERROR','missing reference')")
        self.assertTrue(self.reader.explain_context(1, 2)['model_incomplete'])

    def test_suspension_stops_search(self):
        self.mutate("UPDATE flow_points SET kind='incomplete' WHERE id=31")
        self.assertEqual(self.reader.explain_context(1, 3)['status'], 'incomplete')

    def test_finally_is_not_skipped(self):
        self.mutate("UPDATE flow_edges SET status='incomplete' WHERE id=5")
        self.assertEqual(self.reader.explain_context(1, 3)['status'], 'incomplete')

    def test_unmapped_is_not_unreachable(self):
        self.assertEqual(self.reader.explain_context(1, 5)['status'], 'incomplete')

    def test_union_probe_without_variant_mapping_is_incomplete(self):
        self.mutate("INSERT INTO documents VALUES(5,1,'C.cs','source')")
        context = self.reader.get_block_context(2)
        self.assertEqual([v['name'] for v in context['selected_by']], ['C'])
        self.assertEqual([v['name'] for v in context['compiled_by_without_selection']], ['A'])
        self.assertEqual(self.reader.explain_context(1, 2)['status'], 'found')
        self.mutate("UPDATE documents SET path='Other.cs' WHERE id=1")
        result = self.reader.explain_context(1, 4)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['reason'], 'probe_not_selected_for_reachable_variant')

    def test_selected_probe_without_cfg_mapping_is_incomplete(self):
        self.mutate("UPDATE documents SET path='Other.cs' WHERE id=1; "
                    "INSERT INTO legacy_probe_variants VALUES(4,1)")
        result = self.reader.explain_context(1, 4)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(result['reason'], 'probe_unmapped_in_reachable_variant')

    def test_discarded_shared_conflict_marks_candidate_incomplete(self):
        self.mutate("INSERT INTO analysis_diagnostics VALUES(2,'legacy:1','SHARED_PROBE_CONFLICT_DISCARDED','{}')")
        context = self.reader.get_block_context(1)
        self.assertEqual(context['diagnostics'][0]['code'], 'SHARED_PROBE_CONFLICT_DISCARDED')
        result = self.reader.explain_context(1, 1)
        self.assertEqual(result['status'], 'found')
        self.assertTrue(result['model_incomplete'])

    def test_read_only_and_schema(self):
        with self.assertRaises(sqlite3.OperationalError):
            self.reader.connection.execute('DELETE FROM methods')
        self.reader.close()
        with sqlite3.connect(self.path) as db:
            db.execute("UPDATE analysis_manifest SET value='2' WHERE key='schema_version'")
        db.close()
        with self.assertRaisesRegex(ValueError, 'regenerate'):
            BlockContextReader(self.path)

    def test_schema4_keeps_disabled_context_and_exposes_decision(self):
        self.mutate('''
            ALTER TABLE basic_blocks ADD COLUMN to_trace INTEGER DEFAULT 1;
            UPDATE basic_blocks SET to_trace=0 WHERE id=1;
            UPDATE analysis_manifest SET value='4' WHERE key='schema_version';
            CREATE TABLE trace_selection_profiles(id TEXT,status TEXT,options_json TEXT,metrics_json TEXT);
            CREATE TABLE trace_selection_decisions(legacy_id INTEGER,profile_id TEXT,enabled INTEGER,reason TEXT);
            INSERT INTO trace_selection_profiles VALUES('profile','applied','{"AmbiguityBudget":0.01}','{}');
            INSERT INTO trace_selection_decisions VALUES(1,'profile',0,'suppressed_within_fit_budget');
        ''')
        context = self.reader.get_block_context(1)
        self.assertFalse(context['trace_enabled'])
        self.assertEqual(context['trace_selection']['reason'], 'suppressed_within_fit_budget')
        self.assertEqual(context['trace_selection']['options']['AmbiguityBudget'], .01)
        self.assertEqual(self.reader.explain_context(1, 1)['status'], 'found')

    def test_indexed_scope_no_full_graph_reads(self):
        queries = []
        self.reader.connection.set_trace_callback(queries.append)
        self.reader.explain_context(1, 3)
        for query in queries:
            if any(t in query for t in ('flow_nodes', 'flow_points', 'flow_edges', 'call_sites', 'call_targets')):
                self.assertIn('WHERE', query.upper())

    def test_schema5_interest_evidence(self):
        self.mutate('''UPDATE analysis_manifest SET value='5' WHERE key='schema_version';
            CREATE TABLE trace_selection_profiles(id TEXT,status TEXT,options_json TEXT,metrics_json TEXT);
            CREATE TABLE trace_selection_decisions(legacy_id INTEGER,profile_id TEXT,enabled INTEGER,reason TEXT);
            CREATE TABLE trace_interest_evidence(legacy_id INTEGER,rule TEXT,detail TEXT);
            INSERT INTO trace_interest_evidence VALUES(1,'application_decision','permission true arm');''')
        context = self.reader.get_block_context(1)
        self.assertEqual(context['interest_evidence'], [{'rule': 'application_decision', 'detail': 'permission true arm'}])
        self.assertFalse(context['interest_evidence_has_more'])
        self.assertLessEqual(len(self.reader.cache), 512)

    def test_pagination_and_subgraph_budget(self):
        self.assertEqual(len(self.reader.get_callees(1, limit=1)), 1)
        self.assertEqual(len(self.reader.get_callers(2)), 2)
        self.assertEqual(self.reader.get_reachable_subgraph(1, budget=1)['status'], 'budget_exceeded')
        self.assertEqual({m['id'] for m in self.reader.get_reachable_subgraph(1)['methods']}, {1, 2, 3})
        with self.assertRaises(ValueError):
            self.reader.get_callers(1, limit=0)


class ConfigurationTests(unittest.TestCase):
    def test_filters_and_roots(self):
        command = build_command({'target_solution': 'a.sln', 'target_framework': 'net8.0', 'working_folder': 'test',
                                 'context_include_projects': ['a.csproj'], 'context_exclude_projects': ['b.csproj'],
                                 'context_roots': ['M:C.A'], 'platform': 'AnyCPU'}, ROOT)
        self.assertIn('--include-project', command)
        self.assertIn('--exclude-project', command)
        self.assertIn('--root', command)

    def test_graphify_rejected(self):
        with self.assertRaisesRegex(ValueError, 'retired'):
            build_command({'graphify_python': 'python'}, ROOT)


class ExtractorReaderIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        dll = ROOT / 'RoslynAnalyzer.Tests/bin/Debug/net8.0/RoslynAnalyzer.Tests.dll'
        if not dll.exists():
            raise RuntimeError('Build RoslynAnalyzer.slnx before running integration tests')
        result = subprocess.run(['dotnet', str(dll), '--export', cls.folder.name], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def test_real_extractor_guard_and_linear_methods(self):
        reader = BlockContextReader(Path(self.folder.name) / 'fixture.sqlite')
        try:
            method = reader.rows("SELECT id FROM methods WHERE signature='Sample.A(int)'")[0]['id']
            guard = reader.rows("SELECT id FROM basic_blocks WHERE method_signature LIKE '% A(%' AND reason LIKE '%Fallback%'")[0]['id']
            result = reader.explain_context(method, guard)
            self.assertEqual(result['status'], 'found')
            self.assertFalse(any('call' in event for event in result['witness']))
            graph = reader.get_reachable_subgraph(method)
            self.assertTrue({'Sample.A(int)', 'Sample.B(int)', 'Sample.C(int)'} <= {m['signature'] for m in graph['methods']})
        finally:
            reader.close()

    def test_shared_source_links_preserve_variants(self):
        reader = BlockContextReader(Path(self.folder.name) / 'shared.sqlite')
        try:
            self.assertEqual(reader.rows('SELECT count(*) n FROM methods')[0]['n'], 2)
            for legacy in reader.rows('SELECT id FROM basic_blocks'):
                self.assertEqual(len(reader.get_block_context(legacy['id'])['mapping']), 2)
        finally:
            reader.close()


if __name__ == '__main__':
    unittest.main()
