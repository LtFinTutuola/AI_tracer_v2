"""End-to-end design-time pipeline on a disposable two-method solution."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
DLL = ROOT / 'map_generator/RoslynAnalyzer/bin/Debug/net8.0/RoslynAnalyzer.dll'


class SelectionPipelineTests(unittest.TestCase):
    def test_auto_framework_preserves_mixed_project_targets(self):
        mixed_temporary = tempfile.TemporaryDirectory(prefix='trace-mixed-frameworks-')
        self.addCleanup(mixed_temporary.cleanup)
        mixed = Path(mixed_temporary.name)
        projects = [('Neutral', 'TargetFramework', 'net8.0', 'A'),
                    ('Desktop', 'TargetFramework', 'net8.0-windows', 'B'),
                    ('Multi', 'TargetFrameworks', 'net8.0;net8.0-windows', 'C')]
        project_rows = []
        configuration_rows = []
        for index, (name, framework_property, framework, type_name) in enumerate(projects, 1):
            guid = f'{{00000000-0000-0000-0000-{index:012d}}}'
            generated_item = '<ItemGroup><Compile Include="obj/Generated.cs" /></ItemGroup>' if name == 'Multi' else ''
            (mixed / f'{name}.csproj').write_text(
                f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><{framework_property}>{framework}</{framework_property}></PropertyGroup>{generated_item}</Project>')
            (mixed / f'{name}.cs').write_text(f'public class {type_name} {{ public int Value() {{ return {index}; }} }}')
            if name == 'Multi':
                (mixed / 'obj').mkdir(exist_ok=True)
                (mixed / 'obj/Generated.cs').write_text('public class GeneratedBinding { public int Value() { return 42; } }')
            project_rows.append(f'Project("{{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}}") = "{name}", "{name}.csproj", "{guid}"\nEndProject')
            configuration_rows.extend([
                f'        {guid}.Debug|Any CPU.ActiveCfg = Debug|Any CPU',
                f'        {guid}.Debug|Any CPU.Build.0 = Debug|Any CPU'])
            restored = subprocess.run(['dotnet', 'restore', str(mixed / f'{name}.csproj'), '--ignore-failed-sources'],
                                      text=True, capture_output=True, timeout=120)
            self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)
        solution = mixed / 'Mixed.sln'
        solution.write_text('Microsoft Visual Studio Solution File, Format Version 12.00\n# Visual Studio Version 17\n' +
            '\n'.join(project_rows) + '''
Global
    GlobalSection(SolutionConfigurationPlatforms) = preSolution
        Debug|Any CPU = Debug|Any CPU
    EndGlobalSection
    GlobalSection(ProjectConfigurationPlatforms) = postSolution
''' + '\n'.join(configuration_rows) + '''
    EndGlobalSection
EndGlobal
''')
        output = mixed / 'output'
        run = subprocess.run(['dotnet', str(DLL), str(solution), 'auto', str(output), 'Debug',
                              '--trace-selection', 'false'], text=True, capture_output=True, timeout=180)
        self.assertIn(run.returncode, (0, 2), run.stdout + run.stderr)
        with closing(sqlite3.connect(output / 'basic_blocks.sqlite')) as database:
            manifest = dict(database.execute('SELECT key,value FROM analysis_manifest'))
            pairs = {(item['Name'], item['Framework']) for item in json.loads(manifest['project_frameworks'])}
            self.assertIn(('Neutral', 'net8.0'), pairs)
            self.assertIn(('Desktop', 'net8.0-windows'), pairs)
            self.assertEqual({framework for name, framework in pairs if name.startswith('Multi')},
                             {'net8.0', 'net8.0-windows'})
            variants = {(name, json.loads(options)['EffectiveFramework'])
                        for name, options in database.execute('SELECT name,options FROM project_variants')}
            self.assertEqual(variants, pairs)
            generated = database.execute("SELECT count(*) FROM documents WHERE origin='generated' AND path LIKE '%Generated.cs'").fetchone()[0]
            self.assertEqual(generated, 2, 'one generated document per multitarget variant')
            self.assertEqual(database.execute("SELECT count(*) FROM basic_blocks WHERE file_path LIKE '%\\\\obj\\\\%'").fetchone()[0], 0)

    def test_application_pipeline_and_copy(self):
        policy = self.folder / 'application.json'
        policy.write_text(json.dumps(dict(version=1, name='pipeline-application', rules=[
            dict(type='Target', member='Root', role='operation'),
            dict(type='Target', member='Branch', role='operation')])))
        output = self.folder / 'application-mode'
        arguments = ['--selection-mode', 'application', '--ambiguity-budget', '0',
                     '--observation-policy', str(policy), '--selection-timeout-seconds', '60']
        run = self.run_analyzer(output, *arguments)
        self.assertIn(run.returncode, (0, 2), run.stdout + run.stderr)
        summary = json.loads(run.stdout.splitlines()[-1])
        self.assertEqual(summary['selection']['algorithm'], 'application_observations_v1')
        self.assertIsNone(summary['selection']['first_level'])
        self.assertIsNone(summary['selection']['interest_filter'])
        self.assertTrue((output / 'application-profile-report.json').exists())
        with closing(sqlite3.connect((output / 'basic_blocks.sqlite').as_uri() + '?mode=ro', uri=True)) as database:
            flags = database.execute('SELECT id,to_trace FROM basic_blocks ORDER BY id').fetchall()
            self.assertEqual(database.execute("SELECT value FROM analysis_manifest WHERE key='schema_version'").fetchone()[0], '7')
            self.assertEqual(database.execute('SELECT count(*) FROM application_observations WHERE status=\'modeled\'').fetchone()[0],
                             database.execute('SELECT count(DISTINCT observation_id) FROM application_probe_bindings').fetchone()[0])
            self.assertEqual(database.execute('SELECT count(*) FROM basic_blocks').fetchone()[0], summary['counts']['basic_blocks'])
        copy = self.folder / 'application-copy'
        qualification = subprocess.run(['dotnet', str(DLL), '--select-catalog', str(output / 'basic_blocks.sqlite'), str(copy), *arguments],
                                       text=True, capture_output=True, timeout=120)
        self.assertIn(qualification.returncode, (0, 2), qualification.stdout + qualification.stderr)
        with closing(sqlite3.connect((copy / 'basic_blocks.sqlite').as_uri() + '?mode=ro', uri=True)) as database:
            self.assertEqual(flags, database.execute('SELECT id,to_trace FROM basic_blocks ORDER BY id').fetchall())
        self.assertFalse((self.folder / 'bin/Debug/net8.0/Target.dll').exists(), 'Target application was not compiled')

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='trace-selection-pipeline-')
        cls.folder = Path(cls.temporary.name)
        cls.project = cls.folder / 'Target.csproj'
        cls.project.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>')
        (cls.folder / 'Target.cs').write_text('''public class Target {
            public void Branch(bool x) {
                if(x) { System.Console.WriteLine(1); } else { System.Console.WriteLine(2); }
                System.Console.WriteLine(3);
            }
            public void Root() { Branch(true); Branch(false); }
        }''')
        cls.solution = cls.folder / 'Fixture.sln'
        cls.solution.write_text('''Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Target", "Target.csproj", "{4BC81499-D3A4-471F-B5A5-130748D83EFA}"
EndProject
Global
    GlobalSection(SolutionConfigurationPlatforms) = preSolution
        Debug|Any CPU = Debug|Any CPU
    EndGlobalSection
    GlobalSection(ProjectConfigurationPlatforms) = postSolution
        {4BC81499-D3A4-471F-B5A5-130748D83EFA}.Debug|Any CPU.ActiveCfg = Debug|Any CPU
        {4BC81499-D3A4-471F-B5A5-130748D83EFA}.Debug|Any CPU.Build.0 = Debug|Any CPU
    EndGlobalSection
EndGlobal
''')
        result = subprocess.run(['dotnet', 'restore', str(cls.project), '--ignore-failed-sources'], text=True, capture_output=True, timeout=120)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_analyzer(self, output, *options):
        return subprocess.run(['dotnet', str(DLL), str(self.solution), 'net8.0', str(output), 'Debug', *options],
                              text=True, capture_output=True, timeout=120)

    def test_static_pipeline_and_copy(self):
        output = self.folder / 'static-output'
        result = self.run_analyzer(output, '--selection-mode', 'static', '--ambiguity-budget', '0', '--repeat-policy', 'boundaries')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        path = output / 'basic_blocks.sqlite'
        with closing(sqlite3.connect(path)) as database:
            meta = dict(database.execute('SELECT key,value FROM analysis_manifest'))
            self.assertEqual(meta['schema_version'], '8')
            self.assertEqual(meta['injection_contract'], 'static_probes_v1')
            self.assertEqual(database.execute('SELECT count(*) FROM basic_blocks b JOIN static_flow_decisions d ON d.probe_id=b.id WHERE b.to_trace<>d.enabled').fetchone()[0], 0)
            self.assertTrue(database.execute('SELECT count(*) FROM static_flow_sources').fetchone()[0])
        self.assertTrue((output / 'static-flow-report.json').exists())
        copy = self.folder / 'static-copy'
        result = subprocess.run(['dotnet', str(DLL), '--select-catalog', str(path), str(copy),
                                 '--selection-mode', 'static', '--ambiguity-budget', '0'], text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        with closing(sqlite3.connect(copy / 'basic_blocks.sqlite')) as database:
            self.assertEqual(dict(database.execute('SELECT key,value FROM analysis_manifest'))['injection_contract'], 'static_probes_v1')

    def test_selected_and_disabled_pipeline(self):
        self.assertTrue(DLL.exists(), 'Build RoslynAnalyzer.slnx first')
        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                output = self.folder / str(enabled)
                run = self.run_analyzer(output, '--trace-selection', str(enabled).lower(),
                                        '--selection-samples-per-root', '64', '--selection-timeout-seconds', '30')
                self.assertIn(run.returncode, (0, 2), run.stdout + run.stderr)
                summary = json.loads(run.stdout.splitlines()[-1])
                self.assertEqual(run.returncode, 2 if summary['coverage'] == 'partial' else 0)
                selection = summary['selection']
                self.assertEqual(selection['status'], 'applied' if enabled else 'disabled')
                with closing(sqlite3.connect((output / 'basic_blocks.sqlite').as_uri() + '?mode=ro', uri=True)) as database:
                    self.assertEqual(database.execute('SELECT count(*),sum(to_trace) FROM basic_blocks').fetchone(), (3, 2 if enabled else 3))
                    self.assertEqual(database.execute('SELECT count(*) FROM trace_selection_decisions').fetchone()[0], 3)
                    self.assertEqual(database.execute("SELECT value FROM analysis_manifest WHERE key='schema_version'").fetchone()[0], '7')
                if enabled:
                    self.assertEqual(selection['validation']['SilentExecutions'], 0)
                    self.assertEqual(selection['validation']['EventReductionFraction'], .5)
                    self.assertEqual(selection['qualified_roots'], 2)
                    stages = [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{')]
                    for stage in stages:
                        if stage.get('stage', '').startswith(('selection_', 'verify_final', 'publish_')):
                            self.assertIsNone(stage['project'])
                            self.assertIsNone(stage['document'])
                self.assertFalse(list(self.folder.glob('bin/**/*.dll')), 'Analysis must not compile the target fixture')

    def test_invalid_cli_precedes_workspace_load(self):
        run = self.run_analyzer(self.folder / 'invalid', '--ambiguity-budget', 'true')
        self.assertEqual(run.returncode, 1)
        self.assertNotIn('open_solution', run.stdout)
        self.assertFalse((self.folder / 'invalid').exists())

    def test_interest_filter_pipeline(self):
        output = self.folder / 'interest'
        run = self.run_analyzer(output, '--interest-filter', 'true', '--interest-target-fraction', '.325',
                                '--selection-samples-per-root', '64', '--selection-timeout-seconds', '60')
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        summary = json.loads(run.stdout.splitlines()[-1])
        self.assertEqual(summary['selection']['metrics_scope'], 'experimental_application_interest_profile')
        self.assertEqual(summary['selection']['interest_filter']['uncovered_requirements'], 0)
        self.assertEqual(summary['selection']['interest_filter']['audit']['silent_interest_paths_after_repair'], 0)
        with closing(sqlite3.connect((output / 'basic_blocks.sqlite').as_uri() + '?mode=ro', uri=True)) as database:
            self.assertEqual(database.execute('SELECT count(*) FROM trace_selection_decisions').fetchone()[0], 3)
            self.assertLess(database.execute('SELECT sum(to_trace) FROM basic_blocks').fetchone()[0], 3)


if __name__ == '__main__':
    unittest.main()
