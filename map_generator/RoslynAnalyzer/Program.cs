using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.MSBuild;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace RoslynAnalyzer
{
    class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: RoslynAnalyzer <solution_path> <target_framework> <output_dir>");
                return;
            }

            string solutionPath = args[0];
            string targetFramework = args[1];
            string outputDir = args[2];

            if (!File.Exists(solutionPath))
            {
                Console.WriteLine($"Error: Solution file not found at {solutionPath}");
                return;
            }

            Console.WriteLine("Registering MSBuild...");
            MSBuildLocator.RegisterDefaults();

            using var workspace = MSBuildWorkspace.Create();
            workspace.WorkspaceFailed += (o, e) => Console.WriteLine($"Workspace Error: {e.Diagnostic.Message}");

            Console.WriteLine($"Opening solution: {solutionPath}");
            var solution = await workspace.OpenSolutionAsync(solutionPath);

            var logger = new MarkdownLogger(outputDir);
            var extractor = new BlockExtractor();

            int projectCount = 0;
            foreach (var project in solution.Projects)
            {
                Console.WriteLine($"Analyzing project: {project.Name}");
                projectCount++;

                var compilation = await project.GetCompilationAsync();
                if (compilation == null) continue;

                foreach (var document in project.Documents)
                {
                    if (ShouldProcess(document))
                    {
                        var semanticModel = await document.GetSemanticModelAsync();
                        var syntaxRoot = await document.GetSyntaxRootAsync();
                        
                        if (semanticModel != null && syntaxRoot != null)
                        {
                            var blocks = extractor.ExtractBlocks(semanticModel, syntaxRoot);
                            if (blocks.Any())
                            {
                                logger.LogBlocks(project.Name, document.Name, blocks);
                            }
                        }
                    }
                }
            }

            logger.Save();
            Console.WriteLine($"Processed {projectCount} projects. Log saved to {logger.FilePath}");
        }

        static bool ShouldProcess(Document document)
        {
            if (string.IsNullOrEmpty(document.FilePath)) return false;
            
            var lowerPath = document.FilePath.ToLowerInvariant();
            
            // Explicitly filter to only .cs files
            if (!lowerPath.EndsWith(".cs")) return false;
            
            // Exclude designer and auto-generated files
            if (lowerPath.EndsWith(".designer.cs")) return false;
            if (lowerPath.EndsWith(".xaml.cs")) return false;
            if (lowerPath.EndsWith(".resx")) return false; // Though .resx won't end with .cs, just safe.
            
            return true;
        }
    }
}
