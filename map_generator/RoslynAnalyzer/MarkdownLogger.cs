using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace RoslynAnalyzer
{
    public class MarkdownLogger : IDisposable
    {
        private readonly StreamWriter _sb;
        private readonly string temporary;
        public string FilePath { get; }

        public MarkdownLogger(string outputDir)
        {
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss_fff");
            string fileName = $"[{timestamp}]_basic_blocks.md";
            FilePath = Path.Combine(outputDir, fileName);
            temporary=FilePath+"."+Guid.NewGuid().ToString("N")+".tmp";
            _sb=new StreamWriter(temporary,false,Encoding.UTF8);

            _sb.WriteLine($"# AI Tracer - Estrazione Basic Blocks");
            _sb.WriteLine($"Data di esecuzione: {DateTime.Now:O}");
            _sb.WriteLine();
        }

        public void LogBlocks(string projectName, string documentName, List<TraceableBlock> blocks)
        {
            _sb.WriteLine($"## Progetto: {projectName} | File: {documentName}");
            _sb.WriteLine();

            foreach (var block in blocks)
            {
                _sb.WriteLine($"### Metodo: `{block.MethodName}` (Line: {block.StartLine})");
                _sb.WriteLine($"**Motivazione**: {block.Reason}");
                _sb.WriteLine("```csharp");
                _sb.WriteLine(block.BlockText);
                _sb.WriteLine("```");
                _sb.WriteLine();
            }
        }

        public void Save()
        {
            _sb.Dispose();File.Move(temporary,FilePath);
        }
        public void Dispose() { _sb.Dispose();if(File.Exists(temporary))File.Delete(temporary); }
    }
}
