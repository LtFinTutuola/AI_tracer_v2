using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.MSBuild;
using RoslynAnalyzer;

/// <summary>Read-only target-source probe. It never runs ContextCatalog or publishes a database.</summary>
internal static class SharedCfgProbe
{
    public static async Task<int> RunAsync(string[] args)
    {
        if(args.Length!=7) {
            Console.Error.WriteLine("Usage: --probe-shared-cfg <solution> <framework> <project-a> <project-b> <source> <report.json>");
            return 1;
        }
        if(!MSBuildLocator.IsRegistered) MSBuildLocator.RegisterDefaults();
        var solutionPath=Path.GetFullPath(args[1]); var source=Path.GetFullPath(args[5]);
        var output=Path.GetFullPath(args[6]);
        var orders=new[]{new[]{args[3],args[4]},new[]{args[4],args[3]}};
        var trials=new List<object>();
        foreach(var names in orders) {
            Console.WriteLine(JsonSerializer.Serialize(new {state="opening_solution",order=names}));
            using var workspace=MSBuildWorkspace.Create(new Dictionary<string,string> {
                ["TargetFramework"]=args[2],["Configuration"]="Debug",["Platform"]="AnyCPU",
                ["DesignTimeBuild"]="true",["BuildProjectReferences"]="false",
                ["SkipCompilerExecution"]="true",["AITracerAnalysis"]="true"});
            workspace.LoadMetadataForReferencedProjects=false;
            var failures=new List<string>();workspace.WorkspaceFailed+=(_,e)=>failures.Add(e.Diagnostic.Message);
            var solution=await workspace.OpenSolutionAsync(solutionPath);
            Console.WriteLine(JsonSerializer.Serialize(new {state="solution_loaded",projects=solution.Projects.Count()}));
            foreach(var name in names) {
                var project=solution.Projects.Single(p=>p.Name==name);
                var document=project.Documents.Single(d=>d.FilePath!=null &&
                    string.Equals(Path.GetFullPath(d.FilePath),source,StringComparison.OrdinalIgnoreCase));
                var model=await document.GetSemanticModelAsync() ?? throw new InvalidOperationException("Missing semantic model");
                var root=await document.GetSyntaxRootAsync() ?? throw new InvalidOperationException("Missing syntax root");
                var method=root.DescendantNodes().OfType<MethodDeclarationSyntax>().Single(m=>m.Identifier.Text=="ConvertChars");
                var directBefore=new BlockExtractor().ExtractBlocks(model,root);
                var beforeGraph=ControlFlowGraph.Create(method,model);
                var graphs=new Dictionary<BaseMethodDeclarationSyntax,ControlFlowGraph?>();
                foreach(var declaration in root.DescendantNodes().OfType<BaseMethodDeclarationSyntax>())
                    if(declaration.Body!=null || declaration.ExpressionBody!=null)
                        try {graphs[declaration]=ControlFlowGraph.Create(declaration,model);}catch(ArgumentException){graphs[declaration]=null;}
                var cached=new BlockExtractor().ExtractBlocks(model,root,m=>graphs.GetValueOrDefault(m));
                var directAfter=new BlockExtractor().ExtractBlocks(model,root);
                var afterGraph=ControlFlowGraph.Create(method,model);
                var compile=await project.GetCompilationAsync();
                project.AnalyzerOptions.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.TargetFramework",out var effective);
                var parse=project.ParseOptions as CSharpParseOptions;
                var errorDiagnostics=model.GetDiagnostics().Where(d=>d.Severity==DiagnosticSeverity.Error).Select(d=>d.ToString()).ToArray();
                object Select(List<TraceableBlock> blocks)=>new {
                    count=blocks.Count,
                    offsets=blocks.Select(b=>b.InjectionOffset).OrderBy(x=>x).ToArray(),
                    focus=blocks.Where(b=>b.InjectionOffset is 12253 or 12493).Select(b=>new {b.InjectionOffset,b.StartLine,b.Reason,b.CfgOrdinal}).ToArray()
                };
                var trial=new {
                    order=names,project=name,project_path=project.FilePath,
                    requested_framework=args[2],effective_framework=effective??"<not-reported>",
                    assembly=project.AssemblyName,language_version=parse?.LanguageVersion.ToString(),
                    symbols=parse?.PreprocessorSymbolNames.OrderBy(x=>x).ToArray(),
                    source_sha256=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(source))),
                    workspace_diagnostics_count=failures.Count,
                    workspace_diagnostics_sample=failures.Take(10).ToArray(),
                    source_error_count=errorDiagnostics.Length,source_error_sample=errorDiagnostics.Take(10).ToArray(),
                    direct_before=Select(directBefore),reused_cfg=Select(cached),direct_after=Select(directAfter),
                    cfg_before=Graph(beforeGraph),cfg_reused=Graph(graphs[method]),cfg_after=Graph(afterGraph)
                };
                trials.Add(trial);
                Console.WriteLine(JsonSerializer.Serialize(new {state="project_probed",project=name,
                    direct_before=directBefore.Count,reused_cfg=cached.Count,direct_after=directAfter.Count,
                    source_errors=errorDiagnostics.Length}));
            }
        }
        var report=new {kind="shared_source_cfg_reuse_probe",source,solution=solutionPath,created_utc=DateTime.UtcNow,trials};
        Directory.CreateDirectory(Path.GetDirectoryName(output)!);
        await File.WriteAllTextAsync(output,JsonSerializer.Serialize(report,new JsonSerializerOptions{WriteIndented=true}));
        Console.WriteLine(JsonSerializer.Serialize(new {state="completed",output,trials=trials.Count}));
        return 0;
    }
    private static object? Graph(ControlFlowGraph? graph)
    {
        if(graph==null)return null;
        return graph.Blocks.Where(b=>
            b.Operations.Any(op=>op.Syntax.SpanStart is >= 12150 and <= 12600) ||
            b.BranchValue?.Syntax.SpanStart is >= 12150 and <= 12600)
            .Select(b=>new {b.Ordinal,kind=b.Kind.ToString(),b.IsReachable,condition=b.ConditionKind.ToString(),
                operations=b.Operations.Select(op=>new {kind=op.Kind.ToString(),start=op.Syntax.SpanStart,length=op.Syntax.Span.Length}).ToArray(),
                branch=b.BranchValue==null?null:new {kind=b.BranchValue.Kind.ToString(),start=b.BranchValue.Syntax.SpanStart,length=b.BranchValue.Syntax.Span.Length},
                fallthrough=b.FallThroughSuccessor?.Destination?.Ordinal,
                conditional=b.ConditionalSuccessor?.Destination?.Ordinal,
                fallthrough_semantics=b.FallThroughSuccessor?.Semantics.ToString(),
                conditional_semantics=b.ConditionalSuccessor?.Semantics.ToString()}).ToArray();
    }
}
