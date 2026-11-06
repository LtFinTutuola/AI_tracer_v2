using System.Text.Json;
using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.MSBuild;
using RoslynAnalyzer;

internal static class SharedSourceComparator
{
    private sealed record Projection(
        string MethodSignature,
        int ScopeStartLine,
        int ScopeEndLine,
        int BlockStartLine,
        int BlockEndLine,
        int InjectionLine,
        int InjectionOffset,
        string Reason,
        bool WrapInBlock,
        int StatementEndOffset);

    private sealed record Result(
        string Label,
        string ProjectPath,
        string SourcePath,
        string RequestedTargetFramework,
        string? EffectiveTargetFramework,
        string? AssemblyName,
        string? LanguageVersion,
        IReadOnlyList<string> PreprocessorSymbols,
        IReadOnlyList<string> CompilationErrors,
        IReadOnlyList<Projection> Projection);

    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length != 8 || (args[0] != "--compare-shared" && args[0] != "--compare-shared-solution"))
        {
            Console.Error.WriteLine("Usage: --compare-shared <project-a> <tfm-a> <project-b> <tfm-b> <source> <output.json> <label>");
            Console.Error.WriteLine("   or: --compare-shared-solution <solution> <tfm> <project-a-name> <project-b-name> <source> <output.json> <label>");
            return 1;
        }

        if (!MSBuildLocator.IsRegistered)
            MSBuildLocator.RegisterDefaults();

        Result first;
        Result second;
        if (args[0] == "--compare-shared")
        {
            first = await ExtractAsync(args[7] + "-a", args[1], args[2], args[5]);
            second = await ExtractAsync(args[7] + "-b", args[3], args[4], args[5]);
        }
        else
        {
            (first, second) = await ExtractFromSolutionAsync(args[7], args[1], args[2], args[3], args[4], args[5]);
        }
        var differences = Compare(first.Projection, second.Projection);
        var report = new
        {
            kind = "shared_source_legacy_projection_comparison",
            compared_at_utc = DateTime.UtcNow,
            first,
            second,
            equal = differences.Count == 0,
            difference_count = differences.Count,
            differences
        };
        string output = Path.GetFullPath(args[6]);
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        await File.WriteAllTextAsync(output, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine(JsonSerializer.Serialize(new { state = "completed", output, report.equal, report.difference_count }));
        return differences.Count == 0 ? 0 : 2;
    }

    private static async Task<(Result First, Result Second)> ExtractFromSolutionAsync(
        string label, string solutionPath, string targetFramework, string firstProjectName, string secondProjectName, string sourcePath)
    {
        using var workspace = CreateWorkspace(targetFramework);
        var workspaceFailures = new List<string>();
        workspace.WorkspaceFailed += (_, eventArgs) => workspaceFailures.Add(eventArgs.Diagnostic.Message);
        var solution = await workspace.OpenSolutionAsync(Path.GetFullPath(solutionPath));
        var firstProject = solution.Projects.SingleOrDefault(project => project.Name == firstProjectName)
            ?? throw new InvalidOperationException("Project not found in solution: " + firstProjectName);
        var secondProject = solution.Projects.SingleOrDefault(project => project.Name == secondProjectName)
            ?? throw new InvalidOperationException("Project not found in solution: " + secondProjectName);
        return (
            await ExtractFromProjectAsync(label + "-a", firstProject, targetFramework, sourcePath, workspaceFailures),
            await ExtractFromProjectAsync(label + "-b", secondProject, targetFramework, sourcePath, workspaceFailures));
    }

    private static async Task<Result> ExtractAsync(string label, string projectPath, string targetFramework, string sourcePath)
    {
        projectPath = Path.GetFullPath(projectPath);
        sourcePath = Path.GetFullPath(sourcePath);
        using var workspace = CreateWorkspace(targetFramework);
        var workspaceFailures = new List<string>();
        workspace.WorkspaceFailed += (_, eventArgs) => workspaceFailures.Add(eventArgs.Diagnostic.Message);
        var project = await workspace.OpenProjectAsync(projectPath);
        return await ExtractFromProjectAsync(label, project, targetFramework, sourcePath, workspaceFailures);
    }

    private static MSBuildWorkspace CreateWorkspace(string targetFramework)
    {
        var workspace = MSBuildWorkspace.Create(new Dictionary<string, string>
        {
            ["TargetFramework"] = targetFramework,
            ["Configuration"] = "Debug",
            ["Platform"] = "AnyCPU",
            ["DesignTimeBuild"] = "true",
            ["BuildProjectReferences"] = "false",
            ["SkipCompilerExecution"] = "true",
            ["AITracerAnalysis"] = "true"
        });
        workspace.LoadMetadataForReferencedProjects = false;
        return workspace;
    }

    private static async Task<Result> ExtractFromProjectAsync(string label, Project project, string targetFramework, string sourcePath, IReadOnlyList<string> workspaceFailures)
    {
        var document = project.Documents.SingleOrDefault(d =>
            d.FilePath != null && string.Equals(Path.GetFullPath(d.FilePath), sourcePath, StringComparison.OrdinalIgnoreCase));
        if (document == null)
            throw new InvalidOperationException($"Source file is not a Compile item for project '{project.Name}': {sourcePath}");
        var model = await document.GetSemanticModelAsync() ?? throw new InvalidOperationException("No semantic model");
        var root = await document.GetSyntaxRootAsync() ?? throw new InvalidOperationException("No syntax root");
        var compilation = await project.GetCompilationAsync();
        var parseOptions = project.ParseOptions as CSharpParseOptions;
        project.AnalyzerOptions.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.TargetFramework", out var effectiveTargetFramework);
        var errors = workspaceFailures.Concat(compilation?.GetDiagnostics()
                .Where(d => d.Severity == DiagnosticSeverity.Error)
                .Where(d => !d.Location.IsInSource || string.Equals(d.Location.SourceTree?.FilePath, sourcePath, StringComparison.OrdinalIgnoreCase))
                .Select(d => d.ToString()) ?? Enumerable.Empty<string>())
            .Distinct().OrderBy(x => x).ToArray();
        var projection = new BlockExtractor().ExtractBlocks(model, root)
            .Select(block => new Projection(
                block.MethodSignature, block.ScopeStartLine, block.ScopeEndLine,
                block.BlockStartLine, block.BlockEndLine, block.StartLine,
                block.InjectionOffset, block.Reason, block.WrapInBlock, block.StatementEndOffset))
            .OrderBy(block => block.InjectionOffset)
            .ThenBy(block => JsonSerializer.Serialize(block), StringComparer.Ordinal).ToArray();
        return new Result(label, project.FilePath ?? project.Name, sourcePath, targetFramework,
            effectiveTargetFramework ?? "<not-reported>",
            project.AssemblyName, parseOptions?.LanguageVersion.ToString(),
            parseOptions?.PreprocessorSymbolNames.OrderBy(x => x).ToArray() ?? Array.Empty<string>(), errors, projection);
    }

    private static List<object> Compare(IReadOnlyList<Projection> first, IReadOnlyList<Projection> second)
    {
        var firstByOffset = first.GroupBy(item => item.InjectionOffset).ToDictionary(group => group.Key, group => group.ToArray());
        var secondByOffset = second.GroupBy(item => item.InjectionOffset).ToDictionary(group => group.Key, group => group.ToArray());
        var result = new List<object>();
        foreach (int offset in firstByOffset.Keys.Union(secondByOffset.Keys).OrderBy(offset => offset))
        {
            firstByOffset.TryGetValue(offset, out var firstItems);
            secondByOffset.TryGetValue(offset, out var secondItems);
            string firstJson = JsonSerializer.Serialize(firstItems ?? Array.Empty<Projection>());
            string secondJson = JsonSerializer.Serialize(secondItems ?? Array.Empty<Projection>());
            if (firstJson != secondJson)
                result.Add(new { injection_offset = offset, first = firstItems ?? Array.Empty<Projection>(), second = secondItems ?? Array.Empty<Projection>() });
        }
        if (result.Count == 0 && JsonSerializer.Serialize(first) != JsonSerializer.Serialize(second))
            result.Add(new { injection_offset = (int?)null, first, second, difference = "record_order" });
        return result;
    }
}
