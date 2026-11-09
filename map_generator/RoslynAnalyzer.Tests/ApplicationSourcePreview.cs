using System.Text.Json;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;
using RoslynAnalyzer;

/// <summary>Syntax-only regression on physical samples; never loads/builds a target project.</summary>
internal static class ApplicationSourcePreview
{
    public static async System.Threading.Tasks.Task<int> Run(string[] args)
    {
        if(args.Length<4)throw new ArgumentException("--application-source-preview <new-output> <policy.json> <source.cs> [...]");
        string output=Path.GetFullPath(args[1]);Directory.CreateDirectory(output);
        string db=Path.Combine(output,"syntax-preview.sqlite");if(File.Exists(db))throw new ArgumentException("Use a new preview directory");
        var references=((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator).Select(p=>MetadataReference.CreateFromFile(p)).ToArray();
        var files=args.Skip(3).Select(Path.GetFullPath).ToArray();
        var parse=new CSharpParseOptions(preprocessorSymbols:new[]{"DEBUG","TRACE","NET","NET8_0","NETCOREAPP"});
        using(var workspace=new AdhocWorkspace())using(var catalog=new ContextCatalog(db,"net8.0","Debug")) {
            foreach(string file in files) {
                string name=Path.GetFileName(Path.GetDirectoryName(file)!);
                var project=workspace.AddProject(name,LanguageNames.CSharp).WithParseOptions(parse).WithCompilationOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)).AddMetadataReferences(references);
                var document=project.AddDocument(Path.GetFileName(file),SourceText.From(File.ReadAllText(file)),filePath:file);
                await catalog.AnalyzeDocument(document,catalog.AddProject(document.Project));
            }
            catalog.Complete(finalize:false);
        }
        var options=new TraceSelectionOptions {Mode="application",ObservationPolicy=Path.GetFullPath(args[2]),AmbiguityBudget=0};
        var selection=TraceSelectionEngine.Select(db,options);string profile=TraceSelectionStore.Apply(db,options,selection);TraceSelectionStore.VerifyIntegrity(db);
        var engine=new ApplicationTests.Engine();var task=new AITracer.MsBuildTask.InjectTracesTask {BuildEngine=engine,DatabasePath=db,Compile=files.Select(f=>(ITaskItem)new TaskItem(f)).ToArray(),IntermediateOutputPath=Path.Combine(output,"injection")};
        if(!task.Execute())throw new Exception(string.Join(';',engine.Errors));
        var results=new List<object>();
        foreach(var item in task.ModifiedCompile) {
            var syntax=CSharpSyntaxTree.ParseText(File.ReadAllText(item.ItemSpec),parse);
            var errors=syntax.GetDiagnostics().Where(d=>d.Severity==DiagnosticSeverity.Error).Select(d=>d.ToString()).ToArray();
            results.Add(new {file=item.ItemSpec,syntax_errors=errors});
            if(errors.Length>0)throw new Exception("Target sample injection syntax failure: "+string.Join(';',errors.Take(10)));
        }
        TraceSelectionStore.WriteApplicationReport(output,selection);
        string report=JsonSerializer.Serialize(new {scope="syntax_only_two_source_samples; missing dependencies; NOT a production catalog or target build",profile,selection=selection.Summary,files=results},new JsonSerializerOptions {WriteIndented=true});
        File.WriteAllText(Path.Combine(output,"syntax-preview-report.json"),report);Console.WriteLine(report);return 0;
    }
}
