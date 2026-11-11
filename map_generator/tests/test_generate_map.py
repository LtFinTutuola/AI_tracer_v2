"""Map rendering and publication use real decoder fixtures, never the target build."""
from contextlib import redirect_stdout, redirect_stderr
import importlib
import io
import json
from pathlib import Path
import sqlite3
import sys
import unittest
import shutil
import os
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import generate_map
import test_application_decoder as fixtures


class GenerateMapTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.ApplicationDecoderTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.folder,self.db,self.manifest=self.fixture.folder,self.fixture.db,self.fixture.manifest
        self.log=self.folder/'runtime.log';self.output=self.folder/'map.md'
        self.log.write_text('\n'.join(f'2026-11-09T10:00:00Z||shared||1||{p}' for p in (1,2,3,4))+'\n')

    def run_map(self,*extra,manifest=True):
        args=['--db',str(self.db),'--log',str(self.log),'--output',str(self.output)]
        if manifest: args+=['--build-manifest',str(self.manifest)]
        with redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
            return generate_map.main(args+list(extra))

    def records(self):
        return [json.loads(x) for x in self.output.with_suffix('.jsonl').read_text(encoding='utf-8').splitlines()]

    def test_verified_map_has_calls_returns_and_lossless_events(self):
        self.assertEqual(self.run_map(),0)
        records=self.records();self.assertEqual(records[0]['binding_status'],'verified')
        segment=records[1]
        self.assertEqual([e['probe_id'] for e in segment['observations']],[1,2,3,4])
        self.assertEqual([r['kind'] for r in segment['relations']],['call','local','return'])
        self.assertEqual(records[-1]['counts']['events'],4)
        text=self.output.read_text(encoding='utf-8')
        self.assertIn('```mermaid',text);self.assertIn('call',text);self.assertNotIn('LOOP DETECTED',text)
        nested=next(o for o in segment['operations'] if o['method_id']==2)
        self.assertEqual(nested['parent_enter_event'],0)

    def test_missing_manifest_requires_explicit_exploration(self):
        self.assertEqual(self.run_map(manifest=False),1)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.run_map('--allow-unverified',manifest=False),2)
        self.assertEqual(self.records()[0]['binding_status'],'unverified')

    def test_mismatch_and_failed_generation_preserve_previous_pair(self):
        self.assertEqual(self.run_map(),0)
        before=(self.output.read_bytes(),self.output.with_suffix('.jsonl').read_bytes())
        self.manifest.write_text(self.manifest.read_text().replace('profile','different'))
        self.assertEqual(self.run_map('--allow-unverified'),1)
        self.assertEqual(before,(self.output.read_bytes(),self.output.with_suffix('.jsonl').read_bytes()))

    def test_second_publication_failure_rolls_back_first_file(self):
        first,second=self.folder/'a.md',self.folder/'a.jsonl'
        a,b=self.folder/'new.md',self.folder/'new.jsonl'
        first.write_text('old md');second.write_text('old json');a.write_text('new md');b.write_text('new json')
        replace=generate_map.os.replace
        def fail(source,target):
            if Path(source)==b: raise OSError('synthetic publication failure')
            return replace(source,target)
        with patch.object(generate_map.os,'replace',side_effect=fail):
            with self.assertRaises(OSError):generate_map.publish_pair((a,b),(first,second))
        self.assertEqual(first.read_text(),'old md');self.assertEqual(second.read_text(),'old json')

    def test_graph_limit_keeps_all_jsonl_events_and_escapes_labels(self):
        with self.fixture.connection() as c:
            c.execute("UPDATE application_observations SET evidence=? WHERE id='a-enter'",('A | B "quoted" <tag>',))
        self.assertEqual(self.run_map('--diagram-max-nodes','2'),0)
        text=self.output.read_text(encoding='utf-8')
        self.assertIn('2 eventi omessi dal diagramma',text)
        self.assertIn('&quot;quoted&quot;',text)
        self.assertEqual(len(self.records()[1]['observations']),4)

    def test_source_changes_do_not_invalidate_raw_observations(self):
        source=self.folder/'Source.cs';source.write_text('changed\n')
        with self.fixture.connection() as c:
            c.execute('ALTER TABLE basic_blocks ADD COLUMN file_path TEXT')
            c.execute('ALTER TABLE basic_blocks ADD COLUMN injection_line INTEGER')
            c.execute('ALTER TABLE application_placements ADD COLUMN source_hash TEXT')
            c.execute('UPDATE basic_blocks SET file_path=?,injection_line=1',(str(source),))
            c.execute("UPDATE application_placements SET source_hash='different'")
        self.assertEqual(self.run_map(),2)
        e=self.records()[1]['observations'][0]
        self.assertEqual(e['source_context']['status'],'changed')
        self.assertNotIn('lines',e['source_context'])
        self.assertEqual(e['probe_id'],1)

    def test_legacy_view_has_no_negative_execution_inferences(self):
        with self.fixture.connection() as c:
            c.execute('DROP TABLE analysis_manifest')
        self.assertEqual(self.run_map(manifest=False),2)
        records=self.records()
        self.assertEqual(records[0]['mode'],'legacy_observations')
        self.assertEqual([r['observations'][0]['probe_id'] for r in records if r['kind']=='legacy_segment'],[1,2,3,4])

    def test_import_has_no_config_or_database_side_effects(self):
        with patch.object(generate_map.sqlite3,'connect',side_effect=AssertionError('import opened a database')):
            importlib.reload(generate_map)

    def test_outputs_cannot_overwrite_inputs(self):
        self.assertEqual(self.run_map('--output',str(self.db)),1)
        self.assertTrue(self.db.exists())

    def test_config_defaults_choose_fixed_database_and_latest_log(self):
        shutil.copy2(self.db,self.folder/'basic_blocks.sqlite')
        shutil.copy2(self.manifest,self.folder/'app.aitracer.json')
        latest=self.folder/'z.log';latest.write_text('t||x||1||1\n')
        os.utime(self.log,(1,1));os.utime(latest,(2,2))
        config=self.folder/'config.yaml';config.write_text(json.dumps({'working_folder':str(self.folder)}))
        with patch.dict(sys.modules,{'yaml':SimpleNamespace(safe_load=json.loads)}):
            args=generate_map.arguments(['--config',str(config)])
        self.assertEqual(args.db.name,'basic_blocks.sqlite');self.assertEqual(args.log,latest)
        self.assertEqual(args.build_manifest.name,'app.aitracer.json')

    def test_multiple_manifests_require_explicit_choice(self):
        for name in ('a.aitracer.json','b.aitracer.json'):shutil.copy2(self.manifest,self.folder/name)
        self.assertEqual(self.run_map(manifest=False),1)
        self.assertEqual(self.run_map(),0)


if __name__=='__main__':unittest.main()
