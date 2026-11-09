"""Pre-build extraction and schema 6 application/legacy trace selection."""
from pathlib import Path
import json
import math
import subprocess
import sys


SELECTION_DEFAULTS = {
    'mode': 'legacy', 'observation_policy': '',
    'enabled': True, 'ambiguity_budget': .01, 'max_call_depth': 4,
    'max_candidates': 8, 'samples_per_root': 512, 'max_duration_seconds': 600,
    'max_memory_mb': 512, 'seed': 1729,
    'interest_filter_enabled': False, 'interest_target_fraction': .325,
}
SELECTION_FLAGS = {
    'mode': '--selection-mode', 'observation_policy': '--observation-policy',
    'enabled': '--trace-selection', 'ambiguity_budget': '--ambiguity-budget',
    'max_call_depth': '--selection-max-call-depth', 'max_candidates': '--selection-max-candidates',
    'samples_per_root': '--selection-samples-per-root', 'max_duration_seconds': '--selection-timeout-seconds',
    'max_memory_mb': '--selection-memory-mb', 'seed': '--selection-seed',
    'interest_filter_enabled': '--interest-filter', 'interest_target_fraction': '--interest-target-fraction',
}


def selection_options(value):
    if not isinstance(value, dict) or value.keys() - SELECTION_DEFAULTS.keys():
        raise ValueError('trace_selection must be a mapping with supported option names')
    options = SELECTION_DEFAULTS | value
    for key, item in options.items():
        if key in ('mode', 'observation_policy'):
            valid = type(item) is str
        elif key in ('enabled', 'interest_filter_enabled'):
            valid = type(item) is bool
        elif key in ('ambiguity_budget', 'max_duration_seconds', 'interest_target_fraction'):
            valid = type(item) in (int, float) and math.isfinite(item)
        else:
            valid = type(item) is int
        if not valid:
            raise ValueError('Invalid type for trace_selection.' + key)
    if not 0 <= options['ambiguity_budget'] <= 1 or options['max_duration_seconds'] <= 0:
        raise ValueError('Invalid trace_selection ambiguity budget or duration')
    if options['mode'] not in ('legacy', 'application'):
        raise ValueError('trace_selection.mode must be legacy or application')
    if options['enabled'] and options['mode'] == 'application':
        if options['ambiguity_budget'] != 0 or options['interest_filter_enabled'] or not options['observation_policy']:
            raise ValueError('Application mode requires observation_policy, ambiguity_budget=0 and interest_filter_enabled=false')
    if not 0 < options['interest_target_fraction'] <= 1:
        raise ValueError('Invalid trace_selection.interest_target_fraction')
    if not (0 <= options['max_call_depth'] <= 64 and 1 <= options['max_candidates'] <= 2147483647 and
            64 <= options['samples_per_root'] <= 1000000 and 1 <= options['max_memory_mb'] <= 16384 and
            -2147483648 <= options['seed'] <= 2147483647):
        raise ValueError('Invalid trace_selection limits')
    return options


def build_command(config, directory):
    if not isinstance(config, dict):
        raise ValueError('config.yaml must contain a mapping')
    selection = selection_options(config.get('trace_selection', {}))
    if selection['observation_policy']:
        policy = (directory / selection['observation_policy']).resolve()
        if selection['enabled'] and selection['mode'] == 'application':
            document = json.loads(policy.read_text(encoding='utf-8'))
            if not isinstance(document, dict) or type(document.get('version')) is not int or document['version'] != 1:
                raise ValueError('Application policy version 1 required')
        selection['observation_policy'] = str(policy)
    if any(k.startswith('graphify_') and v not in (None, False, '', []) for k, v in config.items()):
        raise ValueError('Graphify configuration is retired; remove graphify_* settings for schema 5')
    solution = config.get('target_solution')
    folder = config.get('working_folder')
    framework = config.get('target_framework')
    if not solution or not folder or not framework:
        raise ValueError('target_solution, target_framework and working_folder are required')
    output = directory.parent / 'code_analysis' / folder
    command = ['dotnet', 'run', '--project', str(directory / 'RoslynAnalyzer' / 'RoslynAnalyzer.csproj'), '--',
               str(solution), str(framework), str(output), str(config.get('configuration', 'Debug'))]
    if config.get('platform'):
        command += ['--platform', str(config['platform'])]
    for key, flag in [('context_include_projects', '--include-project'),
                      ('context_exclude_projects', '--exclude-project'), ('context_roots', '--root')]:
        values = config.get(key, [])
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise ValueError(key + ' must be a list of strings')
        for value in values:
            command += [flag, value]
    for key, value in selection.items():
        if key == 'observation_policy' and not value:
            continue
        command += [SELECTION_FLAGS[key], str(value).lower() if type(value) is bool else str(value)]
    return command


def main():
    import yaml
    directory = Path(__file__).resolve().parent
    try:
        config = yaml.safe_load((directory / 'config.yaml').read_text(encoding='utf-8'))
        command = build_command(config, directory)
        result = subprocess.run(command, check=False)
        return result.returncode
    except (OSError, ValueError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
