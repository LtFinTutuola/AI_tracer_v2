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
                    self.assertEqual(database.execute("SELECT value FROM analysis_manifest WHERE key='schema_version'").fetchone()[0], '4')
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


if __name__ == '__main__':
    unittest.main()
