import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'experiments'))
from main import build_command, selection_options
import main as orchestrator
from aggressive_probe_experiment import select_aggressively


class SelectionConfigurationTests(unittest.TestCase):
    def test_defaults_and_cli_mapping(self):
        options = selection_options({})
        self.assertEqual(options['ambiguity_budget'], .01)
        self.assertEqual(options['max_duration_seconds'], 600)
        command = build_command({'target_solution': 'test.sln', 'target_framework': 'net8.0',
                                 'working_folder': 'test'}, ROOT)
        self.assertEqual(command[command.index('--ambiguity-budget') + 1], '0.01')
        self.assertEqual(command[command.index('--trace-selection') + 1], 'true')

    def test_zero_and_disabled_are_different(self):
        self.assertTrue(selection_options({'ambiguity_budget': 0})['enabled'])
        self.assertFalse(selection_options({'enabled': False})['enabled'])

    def test_invalid_types_and_limits(self):
        for bad in [None, [], {'ambiguity_budget': True}, {'ambiguity_budget': '1%'},
                    {'ambiguity_budget': float('nan')}, {'ambiguity_budget': float('inf')},
                    {'ambiguity_budget': -1}, {'ambiguity_budget': 1.1}, {'enabled': 1},
                    {'samples_per_root': 63}, {'samples_per_root': 128.0},
                    {'max_call_depth': 65}, {'max_duration_seconds': 0},
                    {'max_memory_mb': False}, {'unknown': 2}]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                selection_options(bad)

    def test_orchestrator_preserves_partial_exit_code(self):
        config = {'target_solution': 'synthetic.sln', 'target_framework': 'net8.0', 'working_folder': 'test'}
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'config.yaml').write_text('{}', encoding='utf-8')
            for code in (0, 2, 1):
                with patch.object(orchestrator, '__file__', str(folder / 'main.py')), \
                        patch.dict(sys.modules, {'yaml': SimpleNamespace(safe_load=lambda text: config)}), \
                        patch.object(orchestrator.subprocess, 'run', return_value=SimpleNamespace(returncode=code)):
                    self.assertEqual(orchestrator.main(), code)


class SelectorParityTests(unittest.TestCase):
    def test_incremental_dotnet_selector_matches_python_reference(self):
        dll = ROOT / 'RoslynAnalyzer.Tests/bin/Debug/net8.0/RoslynAnalyzer.Tests.dll'
        self.assertTrue(dll.exists(), 'Build RoslynAnalyzer.slnx before parity tests')
        rng = random.Random(550117)
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for case in range(16):
                universe = {1, 2, 3, 4, 5, 6, 7, 99, 2**40}
                training, calibration = Counter(), Counter()
                for _ in range(36):
                    word = tuple(rng.choice(sorted(universe - {99})) for _ in range(rng.randrange(0, 9)))
                    training[word] += rng.randrange(0, 40)
                    calibration[word] += rng.randrange(0, 40)
                training = +training
                calibration = +calibration
                protected = {99} | ({1} if case % 2 else set())
                epsilon = [0, .01, .05, .2, 1][case % 5]
                maximum = [1, 2, 4, 8][case % 4]
                selected, evidence = select_aggressively([training, calibration], universe, protected,
                                                         epsilon, maximum)
                words = sorted(training.keys() | calibration.keys())
                payload = {'rows': [{'word': word, 'training': training[word], 'calibration': calibration[word]}
                                    for word in words], 'protected': sorted(protected),
                           'epsilon': epsilon, 'max_candidates': maximum}
                source, output = folder / 'input.json', folder / 'result.json'
                source.write_text(json.dumps(payload), encoding='utf-8')
                completed = subprocess.run(['dotnet', str(dll), '--select-words', str(source), str(output)],
                                           text=True, capture_output=True)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                actual = json.loads(output.read_text(encoding='utf-8'))
                self.assertEqual(actual['disabled'], sorted(universe - selected), f'case {case}')
                self.assertEqual([actual['training'], actual['calibration']], evidence['ambiguous_fit_executions'])
                self.assertEqual(actual['maximum'], evidence['maximum_fit_candidates'])


if __name__ == '__main__':
    unittest.main()
