using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace RoslynAnalyzer
{
    public class MarkdownLogger
    {
        private readonly StringBuilder _sb;
        public string FilePath { get; }

        public MarkdownLogger(string outputDir)
        {
            _sb = new StringBuilder();
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string fileName = $"[{timestamp}]_basic_blocks.md";
            FilePath = Path.Combine(outputDir, fileName);

            _sb.AppendLine($"# AI Tracer - Estrazione Basic Blocks");
            _sb.AppendLine($"Data di esecuzione: {DateTime.Now:O}");
            _sb.AppendLine();
        }

        public void LogBlocks(string projectName, string documentName, List<TraceableBlock> blocks)
        {
            _sb.AppendLine($"## Progetto: {projectName} | File: {documentName}");
            _sb.AppendLine();

            foreach (var block in blocks)
            {
                _sb.AppendLine($"### Metodo: `{block.MethodName}` (Line: {block.StartLine})");
                _sb.AppendLine($"**Motivazione**: {block.Reason}");
                _sb.AppendLine("```csharp");
                _sb.AppendLine(block.BlockText);
                _sb.AppendLine("```");
                _sb.AppendLine();
            }
        }

        public void Save()
        {
            File.WriteAllText(FilePath, _sb.ToString());
        }
    }
}
