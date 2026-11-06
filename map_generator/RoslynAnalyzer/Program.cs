using System.Diagnostics;
using System.Text.Json;
using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.MSBuild;

namespace RoslynAnalyzer;

internal class Program
{
    private static string stage="startup";
    private static string? currentProject,currentDocument;
    private static void Progress(string next,string? project=null,string? document=null,object? details=null) {
        stage=next;currentProject=project;currentDocument=document;
        Console.WriteLine(JsonSerializer.Serialize(new {state="running",stage,project,document,details}));
    }
    public static async Task<int> Main(string[] args) {
        try {return await Run(args);}
        catch(Exception ex) {
            var conflict=ex as LegacyProjectionConflictException;
            Console.Error.WriteLine(JsonSerializer.Serialize(new {state="failed",stage,project=currentProject,document=currentDocument,
                exception_type=ex.GetType().FullName,error=ex.Message,inner_exception_type=ex.InnerException?.GetType().FullName,
                inner_error=ex.InnerException?.Message,stack_trace=ex.StackTrace,
                legacy_projection_conflict=conflict==null?null:new {source=conflict.Second.SourcePath,
                    first=new {origin=conflict.First.Origin,hash=conflict.First.Hash},
                    second=new {origin=conflict.Second.Origin,hash=conflict.Second.Hash},
                    differences=conflict.Differences}}));
            return 1;
        }
    }
    private static async Task<int> Run(string[] args) {
        if(args.FirstOrDefault()=="--select-catalog")
            return await TraceSelectionStore.QualifyCopy(args,(phase,details)=>Progress(phase,details:details));
        var options=AnalyzerOptions.Parse(args);
        var total=Stopwatch.StartNew();var timings=new Dictionary<string,double>();
        Directory.CreateDirectory(options.Output);
        using var cancellation=new CancellationTokenSource();
        ConsoleCancelEventHandler handler=(_,e)=>{e.Cancel=true;cancellation.Cancel();};Console.CancelKeyPress+=handler;
        try {
            using var staging=new CatalogStaging(options.Output);
            using var logger=new MarkdownLogger(options.Output);
            // Workspace and solution references are confined to Extract; the selector only sees SQLite.
            var extracted=await Extract(options,staging.Path,logger,timings,cancellation.Token);
            var clock=Stopwatch.StartNew();
            var selection=TraceSelectionEngine.Select(staging.Path,options.Selection,cancellation.Token,
                (phase,details)=>Progress(phase,details:details));
            timings["selection_ms"]=clock.Elapsed.TotalMilliseconds;
            Progress("verify_final_inputs");
            extracted.Inputs.Verify(cancellation.Token);
            Progress("selection_apply");
            string profile=TraceSelectionStore.Apply(staging.Path,options.Selection,selection,cancellation.Token);
            extracted.Counts["trace_selection_profiles"]=1;extracted.Counts["trace_selection_decisions"]=selection.ProbeCount;extracted.Counts["trace_selection_roots"]=selection.Roots.Count;
            Progress("verify_final_catalog");
            extracted.Inputs.Verify(cancellation.Token);TraceSelectionStore.VerifyIntegrity(staging.Path);
            cancellation.Token.ThrowIfCancellationRequested();Progress("publish_catalog");clock.Restart();
            string destination=Path.Combine(options.Output,"basic_blocks.sqlite");CatalogPublication.Publish(staging.Path,destination);
            timings["publication_ms"]=clock.Elapsed.TotalMilliseconds;logger.Save();
            using var resultDb=new Microsoft.Data.Sqlite.SqliteConnection(new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder {DataSource=destination,Mode=Microsoft.Data.Sqlite.SqliteOpenMode.ReadOnly,Pooling=false}.ToString());
            resultDb.Open();using var query=resultDb.CreateCommand();query.CommandText="SELECT value FROM analysis_manifest WHERE key='coverage'";string coverage=(string)query.ExecuteScalar()!;
            string summary=JsonSerializer.Serialize(new {state="published",coverage,projects=extracted.Projects,counts=extracted.Counts,timings_ms=timings,total_ms=total.Elapsed.TotalMilliseconds,
                selection_profile_id=profile,selection=selection.Summary,
                database_bytes=new FileInfo(destination).Length,peak_working_set_bytes=Process.GetCurrentProcess().PeakWorkingSet64,database=destination,log=logger.FilePath});
            File.WriteAllText(Path.Combine(options.Output,"analysis-summary.json"),summary);
            Console.WriteLine(summary);
            return coverage=="partial"?2:0;
        } finally {Console.CancelKeyPress-=handler;}
    }
    private sealed record Extracted(InputRegistry Inputs,Dictionary<string,long> Counts,int Projects);
    private static async Task<Extracted> Extract(AnalyzerOptions options,string staging,MarkdownLogger logger,Dictionary<string,double> timings,CancellationToken token)
    {
        Progress("register_msbuild");MSBuildLocator.RegisterDefaults();
        using var workspace=MSBuildWorkspace.Create(new Dictionary<string,string> {
            ["TargetFramework"]=options.Framework,["Configuration"]=options.Configuration,["Platform"]=options.Platform,
            ["DesignTimeBuild"]="true",["BuildProjectReferences"]="false",["SkipCompilerExecution"]="true",["AITracerAnalysis"]="true"});
        workspace.LoadMetadataForReferencedProjects=false;
        var errors=new List<string>();workspace.WorkspaceFailed+=(_,e)=>errors.Add(e.Diagnostic.Message);
        var inputs=new InputRegistry();inputs.Track(options.Solution);
        Progress("open_solution");var clock=Stopwatch.StartNew();
        var solution=await workspace.OpenSolutionAsync(options.Solution,cancellationToken:token);
        timings["load_ms"]=clock.Elapsed.TotalMilliseconds;
        var loaded=solution.Projects.ToArray();var projects=loaded.Where(options.Includes).ToArray();
        if(projects.Length==0)throw new ArgumentException("Project filters selected no C# projects");
        Progress("project_scope",details:new {loaded=loaded.Select(p=>p.FilePath).ToArray(),included=projects.Select(p=>p.FilePath).ToArray(),excluded=loaded.Except(projects).Select(p=>p.FilePath).ToArray()});
        using var catalog=new ContextCatalog(staging,options.Framework,options.Configuration,inputs);
        catalog.Batch(()=> {foreach(var error in errors)catalog.Diagnostic("workspace","LOAD_DIAGNOSTIC",error);
            catalog.Meta("platform",options.Platform);catalog.Meta("suggested_roots",JsonSerializer.Serialize(options.Roots));
            catalog.Meta("project_scope",JsonSerializer.Serialize(projects.Select(p=>p.FilePath)));});
        clock.Restart();long writesBefore=catalog.WriteTicks;
        foreach(var project in projects) {
            token.ThrowIfCancellationRequested();Progress("analyze_project",project.Name);
            long variant=catalog.AddProject(project);var projectTime=Stopwatch.StartNew();
            foreach(var document in project.Documents) {
                Progress("analyze_document",project.Name,document.FilePath??document.Name);
                await catalog.AnalyzeDocument(document,variant,token:token);
                if(catalog.LastNewProbes.Count>0)logger.LogBlocks(project.Name,document.Name,catalog.LastNewProbes.ToList());
                if(catalog.LastNewCount>0||catalog.LastReusedCount>0||catalog.LastDiscardedConflictCount>0)
                    Progress("shared_projection_reconciled",project.Name,document.FilePath??document.Name,
                        new {new_points=catalog.LastNewCount,reused_points=catalog.LastReusedCount,discarded_conflicts=catalog.LastDiscardedConflictCount});
            }
            foreach(var document in await project.GetSourceGeneratedDocumentsAsync(token)) {
                Progress("analyze_generated_document",project.Name,document.FilePath??document.Name);
                await catalog.AnalyzeDocument(document,variant,true,token);
            }
            Progress("project_completed",project.Name,details:new {elapsed_ms=projectTime.Elapsed.TotalMilliseconds,
                graphs=catalog.GraphsCreated,documents=catalog.DocumentsAnalyzed,shared_probe_new=catalog.SharedProbeNew,
                shared_probe_reused=catalog.SharedProbeReused,shared_probe_discarded_conflicts=catalog.SharedProbeDiscardedConflicts});
        }
        timings["analysis_and_write_ms"]=clock.Elapsed.TotalMilliseconds;
        timings["analysis_sql_write_ms"]=(catalog.WriteTicks-writesBefore)*1000.0/Stopwatch.Frequency;
        timings["analysis_excluding_sql_ms"]=Math.Max(0,timings["analysis_and_write_ms"]-timings["analysis_sql_write_ms"]);
        Progress("verify_inputs");clock.Restart();inputs.Verify(token);timings["verify_inputs_ms"]=clock.Elapsed.TotalMilliseconds;
        Progress("resolve_and_validate");clock.Restart();catalog.Complete(token,verifyInputs:false,progress:phase=>Progress(phase),finalize:false);
        timings["resolve_and_validate_ms"]=clock.Elapsed.TotalMilliseconds;
        foreach(var timing in catalog.FinalizationMilliseconds)timings[timing.Key]=timing.Value;
        timings["sql_write_ms"]=catalog.WriteTicks*1000.0/Stopwatch.Frequency;
        catalog.Batch(()=> {catalog.Meta("timings_ms",JsonSerializer.Serialize(timings));catalog.Meta("peak_working_set_bytes",Process.GetCurrentProcess().PeakWorkingSet64.ToString());});
        return new(inputs,catalog.Counts,projects.Length);
    }
    public static bool ShouldProcess(Document document) {
        var path=document.FilePath?.ToLowerInvariant();return path!=null && path.EndsWith(".cs") && !path.EndsWith(".designer.cs") && !path.EndsWith(".xaml.cs");
    }
}

public sealed class AnalyzerOptions
{
    public string Solution {get;private set;}="";
    public string Framework {get;private set;}="";
    public string Output {get;private set;}="";
    public string Configuration {get;private set;}="Debug";
    public string Platform {get;private set;}="AnyCPU";
    public List<string> Roots {get;}=new();
    public TraceSelectionOptions Selection {get;private set;}=new();
    private readonly HashSet<string> include=new(StringComparer.OrdinalIgnoreCase),exclude=new(StringComparer.OrdinalIgnoreCase);
    public bool Includes(Project p)=>p.Language==LanguageNames.CSharp && (include.Count==0 || include.Contains(Path.GetFullPath(p.FilePath??p.Name))) && !exclude.Contains(Path.GetFullPath(p.FilePath??p.Name));
    public static AnalyzerOptions Parse(string[] args) {
        if(args.Length<3)throw new ArgumentException("Usage: RoslynAnalyzer <solution> <framework> <output> [configuration] [- [roots [platform]]] [--platform value] [--include-project path] [--exclude-project path] [--root symbol]");
        var o=new AnalyzerOptions {Solution=Path.GetFullPath(args[0]),Framework=args[1],Output=Path.GetFullPath(args[2])};
        if(!File.Exists(o.Solution))throw new FileNotFoundException("Solution not found",o.Solution);
        var positional=new List<string>();int i=3;
        while(i<args.Length && !args[i].StartsWith("--"))positional.Add(args[i++]);
        if(positional.Count>4)throw new ArgumentException("Too many positional arguments");
        if(positional.Count>0)o.Configuration=positional[0];
        if(positional.Count>1 && positional[1]!="-")throw new ArgumentException("Graphify envelopes are retired; regenerate with the schema 4 Roslyn call graph");
        if(positional.Count>2)o.Roots.AddRange(positional[2].Split(';',StringSplitOptions.RemoveEmptyEntries));
        if(positional.Count>3)o.Platform=positional[3];
        while(i<args.Length) {
            string option=args[i++];if(i>=args.Length)throw new ArgumentException("Missing value for "+option);string value=args[i++];
            switch(option) {
                case "--platform":o.Platform=value;break;
                case "--configuration":o.Configuration=value;break;
                case "--root":o.Roots.Add(value);break;
                case "--include-project":o.include.Add(Path.GetFullPath(value,Path.GetDirectoryName(o.Solution)!));break;
                case "--exclude-project":o.exclude.Add(Path.GetFullPath(value,Path.GetDirectoryName(o.Solution)!));break;
                default:o.Selection=TraceSelectionOptions.ParseOption(o.Selection,option,value);break;
            }
        }
        o.Selection.Validate();return o;
    }
}
