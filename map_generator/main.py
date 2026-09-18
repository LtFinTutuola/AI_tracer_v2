import os
import sys
import yaml
import subprocess
from datetime import datetime

def main():
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    
    if not os.path.exists(config_path):
        print(f"Error: Config file not found at {config_path}")
        sys.exit(1)
        
    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
        
    test_solution_path = config.get('test_solution_path')
    test_target_framework = config.get('test_target_framework')
    
    if not test_solution_path:
        print("Error: 'test_solution_path' not defined in config.yaml")
        sys.exit(1)
        
    # Prepare output directory
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    out_dir = os.path.join(repo_root, 'code_analysis')
    os.makedirs(out_dir, exist_ok=True)
    
    # Path to the C# Analyzer project
    analyzer_proj = os.path.join(os.path.dirname(__file__), 'RoslynAnalyzer', 'RoslynAnalyzer.csproj')
    
    print(f"Starting Roslyn Analysis on: {test_solution_path}")
    print(f"Target Framework: {test_target_framework}")
    print(f"Output Directory: {out_dir}")
    
    # Run the C# project
    cmd = [
        "dotnet", "run",
        "--project", analyzer_proj,
        "--",
        test_solution_path,
        str(test_target_framework),
        out_dir
    ]
    
    try:
        result = subprocess.run(cmd, check=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running RoslynAnalyzer: {e}")
        sys.exit(e.returncode)
        
    print("Analysis complete.")

if __name__ == '__main__':
    main()
