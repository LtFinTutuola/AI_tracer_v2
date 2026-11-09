using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;
using Microsoft.Data.Sqlite;
using RoslynAnalyzer;

// No target solution load, Program.Main invocation or Graphify execution.
if(args.FirstOrDefault()=="--select-words") {TraceSelectionTests.SelectWords(args[1],args[2]);return;}
if(args.FirstOrDefault()=="--application-source-preview") {Environment.ExitCode=await ApplicationSourcePreview.Run(args);return;}
if(args.FirstOrDefault()=="--probe-shared-cfg") {Environment.ExitCode=await SharedCfgProbe.RunAsync(args);return;}
if(args.FirstOrDefault()?.StartsWith("--compare-shared")==true) {Environment.ExitCode=await SharedSourceComparator.RunAsync(args);return;}
var export=args.Length==2 && args[0]=="--export"?Path.GetFullPath(args[1]):null;
var directory=export??Path.Combine(Path.GetTempPath(),"light-context-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(directory);
int assertions=0;
void Assert(bool valid,string message) {assertions++;if(!valid)throw new Exception(message);}
void Throws<T>(Action action,string message) where T:Exception {try {action();}catch(T){assertions++;return;}throw new Exception(message);}
MetadataReference[] references=((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator).Select(p=>MetadataReference.CreateFromFile(p)).ToArray();
using var workspace=new AdhocWorkspace();
Document Document(string name,string source,string? file=null)=>workspace.AddProject(name,LanguageNames.CSharp)
    .WithCompilationOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary))
    .AddMetadataReferences(references).AddDocument(name+".cs",SourceText.From(source),filePath:file??Path.Combine(directory,name+".cs"));
var source="""
using System;
using System.Threading.Tasks;
interface I { void Run(); }
class Sample : I {
  public int P { get { return 1; } set { } }
  public int Expression => 3;
  public void A(int x) { if(x==1) { return; } B(x); }
  public void B(int x) { C(x); }
  public void C(int x) { Console.WriteLine(x); }
  public int Identity(int x) => x;
  public string Identity(string x) => x;
  public string Overload() => Identity("x");
  public int Virtual(Base b) => b.V();
  public void Creation() { var value = new Newed(Identity(1)) { P = Identity(2) }; }
  public int Generic<T>(T value) => 1;
  public int Caller(int x) { if(x==0) return Identity(Identity(x)); B(x); B(x); return Generic(x); }
  public void Properties() { P += Identity(1); P++; P = Identity(2); }
  public void Run() { }
  public void Open(I i, dynamic d) { i.Run(); Action a = Run; a(); d.Run(); }
  public int Recursive(int n) { return n==0?0:Recursive(n-1); }
  public void Loop(int n) { while(n>0) { n--; B(n); } }
  public void Nested() { int Local(int x) => x+1; Func<int,int> f=x=>x*2; Console.WriteLine(Local(f(2))); }
  public void Exceptional() { try { throw new Exception(); } catch(Exception) { B(1); } finally { B(2); } }
  public async Task Async() { await Task.Delay(1); B(1); }
  public System.Collections.Generic.IEnumerable<int> Iterator() { yield return 1; }
}
class Base { public virtual int V() => 1; }
class Child : Base { public override int V() => 2; }
class Newed { public Newed(int x) {} public int P { get; set; } }
""";
File.WriteAllText(Path.Combine(directory,"Fixture.cs"),source);
var document=Document("Fixture",source);
var root=await document.GetSyntaxRootAsync();var model=await document.GetSemanticModelAsync();
Assert(!model!.GetDiagnostics().Any(d=>d.Severity==DiagnosticSeverity.Error),"Fixture must bind");
var legacy=new BlockExtractor().ExtractBlocks(model,root!);
var path=Path.Combine(directory,"fixture.sqlite");if(File.Exists(path))File.Delete(path);
using(var catalog=new ContextCatalog(path,"net8.0","Debug")) {
    var variant=catalog.AddProject(document.Project);var actual=await catalog.AnalyzeDocument(document,variant);
    var expected=LegacyProjectionDiagnostics.Create(document.Project,"x","net8.0",document.FilePath!,legacy.Select(b=>ContextCatalog.ToRecord(b,"Fixture",document.FilePath!)));
    var result=LegacyProjectionDiagnostics.Create(document.Project,"x","net8.0",document.FilePath!,actual.Select(b=>ContextCatalog.ToRecord(b,"Fixture",document.FilePath!)));
    Assert(expected.Records.SequenceEqual(result.Records),"Legacy selection parity");
    int top=root!.DescendantNodes().Count(n=>n is BaseMethodDeclarationSyntax or AccessorDeclarationSyntax || n is PropertyDeclarationSyntax {ExpressionBody:not null});
    Assert(catalog.CfgRequests==top+2,"Exactly one CFG request per body including local/lambda");
    var generated=Document("Generated","class Generated { public void M() { System.Console.WriteLine(1); } }");
    var generatedProbes=await catalog.AnalyzeDocument(generated,catalog.AddProject(generated.Project),true);
    Assert(generatedProbes.Count==0,"Generated code context does not add probes");
    var invalid=Document("Invalid","class Invalid { void M() { Unknown(); } }");
    await catalog.AnalyzeDocument(invalid,catalog.AddProject(invalid.Project));
    var topDocument=Document("TopLevel","System.Console.WriteLine(1);");
    topDocument=topDocument.Project.WithCompilationOptions(new CSharpCompilationOptions(OutputKind.ConsoleApplication)).GetDocument(topDocument.Id)!;
    await catalog.AnalyzeDocument(topDocument,catalog.AddProject(topDocument.Project),true);
    catalog.Complete();
}
using(var db=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=path,Pooling=false}.ToString())) {
    db.Open();long Count(string sql){using var cmd=db.CreateCommand();cmd.CommandText=sql;return Convert.ToInt64(cmd.ExecuteScalar());}
    Assert(Count("SELECT count(*) FROM methods WHERE parent_id IS NOT NULL")==2,"Nested bodies");
    Assert(Count("SELECT count(*) FROM methods WHERE status='unsupported'")==0,"Supported body forms including accessors and expression properties");
    Assert(Count("SELECT count(*) FROM methods WHERE signature LIKE '%Sample.B(%' OR signature LIKE '%Sample.C(%'")==2,"Linear methods retained");
    Assert(Count("SELECT count(*) FROM call_sites WHERE resolution='dispatch_open'")>0,"Interface remains open");
    Assert(Count("SELECT count(*) FROM call_sites WHERE resolution='delegate_open'")>0,"Delegate remains open");
    Assert(Count("SELECT count(*) FROM call_sites WHERE resolution='dynamic_open'")>0,"Dynamic remains open");
    Assert(Count("SELECT count(*) FROM call_targets t JOIN methods m ON m.id=t.method_id WHERE t.evidence='declared_candidate' AND m.signature='Base.V()'")==1,"Declared virtual candidate retained");
    Assert(Count("SELECT count(*) FROM call_targets t JOIN methods m ON m.id=t.method_id WHERE m.signature='Child.V()'")==0,"No override expansion");
    Assert(Count("SELECT count(*) FROM call_targets t JOIN methods m ON m.id=t.method_id WHERE m.signature LIKE '%Generic%'")==1,"Generic identity binds");
    Assert(Count("SELECT count(*) FROM call_sites WHERE target_signature LIKE 'Sample.P.get%'")==2,"Compound/increment getters");
    Assert(Count("SELECT count(*) FROM call_sites WHERE target_signature LIKE 'Sample.P.set%'")==3,"Compound/increment/simple setters");
    Assert(Count("SELECT count(*) FROM flow_points WHERE kind='incomplete'")>=2,"Suspensions explicit");
    Assert(Count("SELECT count(*) FROM flow_edges WHERE status='incomplete'")>0,"Finally transfers incomplete");
    Assert(Count("SELECT count(*) FROM analysis_diagnostics WHERE code='SEMANTIC_ERROR'")>0,"Semantic errors retained");
    Assert(Count("SELECT count(*) FROM documents WHERE origin='generated'")==2,"Generated provenance including top-level fixture");
    Assert(Count("SELECT count(*) FROM sqlite_master WHERE name IN ('cfg_operations','dominators','postdominators','path_families','context_methods','method_summaries')")==0,"No heavy tables");
    Assert(Count("SELECT count(*) FROM legacy_block_links WHERE point_id IS NOT NULL")>0,"Direct legacy mappings");
    using(var cmd=db.CreateCommand()) {
        cmd.CommandText="SELECT s.target_signature,p.start FROM call_sites s JOIN flow_points p ON p.id=s.point_id JOIN methods m ON m.id=s.method_id WHERE m.signature='Sample.Creation()' ORDER BY p.position";
        using var read=cmd.ExecuteReader();var order=new List<string>();while(read.Read())order.Add(read.GetString(0));
        Assert(order.Count==4 && order[0].Contains("Identity") && order[1].Contains("Newed.Newed") && order[2].Contains("Identity") && order[3].Contains("P.set"),"Constructor before object initializer, after arguments");
    }
    using(var cmd=db.CreateCommand()) {
        cmd.CommandText="SELECT p.start FROM call_sites s JOIN flow_points p ON p.id=s.point_id JOIN methods m ON m.id=s.method_id WHERE m.signature='Sample.Caller(int)' AND s.target_signature='Sample.Identity(int)' ORDER BY p.position";
        using var read=cmd.ExecuteReader();var order=new List<int>();while(read.Read())order.Add(read.GetInt32(0));
        Assert(order.Count==2 && order[0]>order[1],"Nested invocation evaluates inner first");
    }
    using var foreign=db.CreateCommand();foreign.CommandText="PRAGMA foreign_key_check";using var r=foreign.ExecuteReader();Assert(!r.Read(),"Foreign keys");
}
// Canonical comparison and precise shared-source conflict diagnostics.
var records=legacy.Select(b=>ContextCatalog.ToRecord(b,"Fixture",document.FilePath!)).ToArray();
var first=LegacyProjectionDiagnostics.Create(null,"a","net8.0",document.FilePath!,records);
var reordered=LegacyProjectionDiagnostics.Create(null,"b","net8.0",document.FilePath!,records.Reverse());
Assert(first.Records.SequenceEqual(reordered.Records),"Projection order independent");
Assert(LegacyProjectionDiagnostics.Diff(first,reordered).Count==0,"No false field diff");
if(records.Length>0) {
    var modified=records.Select(r=>new BasicBlockRecord {MethodSignature=r.MethodSignature,ScopeStartLine=r.ScopeStartLine,ScopeEndLine=r.ScopeEndLine,BlockStartLine=r.BlockStartLine,BlockEndLine=r.BlockEndLine,InjectionLine=r.InjectionLine,InjectionOffset=r.InjectionOffset,Reason="changed"}).ToArray();
    var second=LegacyProjectionDiagnostics.Create(null,"b","net8.0",document.FilePath!,modified);
    Assert(LegacyProjectionDiagnostics.Diff(first,second).Any(d=>d.Fields.Any(f=>f.Field=="Reason")),"Conflict field evidence");
    var baseline=first.Records.First();
    foreach(var (changed,field) in new (LegacyProjectionRecord,string)[] {
        (baseline with {Reason="other"},"Reason"),
        (baseline with {MethodSignature="other"},"MethodSignature"),
        (baseline with {BlockStartLine=baseline.BlockStartLine+1},"BlockStartLine"),
        (baseline with {WrapInBlock=!baseline.WrapInBlock},"WrapInBlock"),
        (baseline with {ToTrace=!baseline.ToTrace},"ToTrace")
    }) {
        var fields=LegacyProjectionDiagnostics.CompareAtOffset(baseline,changed);
        Assert(fields.Count==1 && fields[0].Field==field,"Exact shared-offset conflict field: "+field);
    }
}
var sharedPath=Path.Combine(directory,"Shared.cs");const string sharedSource="class Shared { public void M(int x) { if(x==1) return; System.Console.WriteLine(x); } }";
File.WriteAllText(sharedPath,sharedSource);
var sharedOne=Document("SharedOne",sharedSource,sharedPath);var sharedTwo=Document("SharedTwo",sharedSource,sharedPath);
var sharedDb=Path.Combine(directory,"shared.sqlite");if(File.Exists(sharedDb))File.Delete(sharedDb);
using(var catalog=new ContextCatalog(sharedDb,"net8.0","Debug")) {
    await catalog.AnalyzeDocument(sharedOne,catalog.AddProject(sharedOne.Project));
    await catalog.AnalyzeDocument(sharedTwo,catalog.AddProject(sharedTwo.Project));catalog.Complete();
}
var conditionalText=new StringBuilder("class Conditional { void M(int x) {\n");
for(int n=0;n<14;n++)conditionalText.Append($"if(x=={n}) {{ System.Console.WriteLine(x); }}\n");
conditionalText.Append("#if DIFFERENT\nif(x==14) { System.Console.WriteLine(x); }\nif(x==15) { System.Console.WriteLine(x); }\n#endif\n} }");
string conditionalSource=conditionalText.ToString();
string conditionalPath=Path.Combine(directory,"Conditional.cs");File.WriteAllText(conditionalPath,conditionalSource);
var conditionalOne=Document("ConditionalOne",conditionalSource,conditionalPath);
var conditionalTwo=Document("ConditionalTwo",conditionalSource,conditionalPath);
conditionalTwo=conditionalTwo.Project.WithParseOptions(new CSharpParseOptions(preprocessorSymbols:new[]{"DIFFERENT"})).GetDocument(conditionalTwo.Id)!;
async Task<int[]> Offsets(Document doc) {
    var model=await doc.GetSemanticModelAsync();var root=await doc.GetSyntaxRootAsync();
    return new BlockExtractor().ExtractBlocks(model!,root!).Select(b=>b.InjectionOffset).OrderBy(x=>x).ToArray();
}
var firstOffsets=await Offsets(conditionalOne);var secondOffsets=await Offsets(conditionalTwo);
Assert(firstOffsets.Length==14 && secondOffsets.Length==16 && firstOffsets.All(secondOffsets.Contains),"Shared fixture is exactly 14 common plus 2 exclusive");
var unionExpected=firstOffsets.Union(secondOffsets).OrderBy(x=>x).ToArray();
async Task<string> BuildUnion(bool reverse,bool failSecond) {
    string dbPath=Path.Combine(directory,"union-"+reverse+"-"+failSecond+".sqlite");
    if(File.Exists(dbPath))File.Delete(dbPath);
    var ordered=reverse?new[]{conditionalTwo,conditionalOne}:new[]{conditionalOne,conditionalTwo};
    using(var catalog=new ContextCatalog(dbPath,"net8.0","Debug")) {
        var firstVariant=catalog.AddProject(ordered[0].Project);
        await catalog.AnalyzeDocument(ordered[0],firstVariant);
        var secondVariant=catalog.AddProject(ordered[1].Project);
        if(failSecond) {
            using(var db=new SqliteConnection($"Data Source={dbPath};Pooling=False")) {
                db.Open();using var trigger=db.CreateCommand();trigger.CommandText=$"CREATE TRIGGER fail_second BEFORE INSERT ON shared_projection_stats WHEN NEW.variant_id={secondVariant} BEGIN SELECT RAISE(ABORT,'test rollback'); END";trigger.ExecuteNonQuery();
            }
            Throws<SqliteException>(()=>catalog.AnalyzeDocument(ordered[1],secondVariant).GetAwaiter().GetResult(),"Injected transaction failure not observed");
            using(var db=new SqliteConnection($"Data Source={dbPath};Pooling=False")) {
                db.Open();using var query=db.CreateCommand();query.CommandText="SELECT count(*) FROM basic_blocks";
                Assert(Convert.ToInt32(query.ExecuteScalar())==(reverse?16:14),"Failed document left rows behind");
                query.CommandText="DROP TRIGGER fail_second";query.ExecuteNonQuery();
            }
        }
        await catalog.AnalyzeDocument(ordered[1],secondVariant);
        Assert(catalog.SharedProbeNew==16 && catalog.SharedProbeReused==14,"Union counters after committed documents");
        catalog.Complete();
    }
    return dbPath;
}
var unionForward=await BuildUnion(false,true);var unionReverse=await BuildUnion(true,false);
IReadOnlyList<string> UnionRows(string dbPath) {
    using var db=new SqliteConnection($"Data Source={dbPath};Pooling=False");db.Open();using var cmd=db.CreateCommand();
    cmd.CommandText="SELECT injection_offset||':'||method_signature||':'||reason||':'||wrap_in_block FROM basic_blocks ORDER BY injection_offset";
    using var read=cmd.ExecuteReader();var rows=new List<string>();while(read.Read())rows.Add(read.GetString(0));return rows;
}
Assert(UnionRows(unionForward).SequenceEqual(UnionRows(unionReverse)),"Union independent of project order except numeric IDs");
using(var db=new SqliteConnection($"Data Source={unionForward};Pooling=False")) {
    db.Open();using var cmd=db.CreateCommand();
    cmd.CommandText="SELECT injection_offset FROM basic_blocks ORDER BY injection_offset";
    using(var read=cmd.ExecuteReader()){var actual=new List<int>();while(read.Read())actual.Add(read.GetInt32(0));Assert(actual.SequenceEqual(unionExpected),"Exactly 16 physical probe offsets");}
    cmd.CommandText="SELECT count(*) FROM legacy_probe_variants";Assert(Convert.ToInt32(cmd.ExecuteScalar())==30,"14 shared provenance pairs plus 2 exclusive");
    cmd.CommandText="SELECT count(*) FROM legacy_block_links l JOIN basic_blocks b ON b.id=l.legacy_id JOIN methods m ON m.id=l.method_id JOIN project_variants v ON v.id=m.variant_id WHERE b.injection_offset IN (SELECT injection_offset FROM basic_blocks WHERE injection_offset NOT IN ("+string.Join(',',firstOffsets)+")) AND v.name='ConditionalOne'";
    Assert(Convert.ToInt32(cmd.ExecuteScalar())==0,"Exclusive probes have no invented first-variant CFG links");
    cmd.CommandText="SELECT count(*) FROM shared_projection_stats WHERE new_points=14 AND reused_points=0 OR new_points=2 AND reused_points=14";
    Assert(Convert.ToInt32(cmd.ExecuteScalar())==2,"Per-project/file reconciliation stats");
}
var conditionalThree=Document("ConditionalThree",conditionalSource,conditionalPath);
var threeDb=Path.Combine(directory,"union-three.sqlite");
using(var catalog=new ContextCatalog(threeDb,"net8.0","Debug")) {
    await catalog.AnalyzeDocument(conditionalOne,catalog.AddProject(conditionalOne.Project));
    await catalog.AnalyzeDocument(conditionalTwo,catalog.AddProject(conditionalTwo.Project));
    await catalog.AnalyzeDocument(conditionalThree,catalog.AddProject(conditionalThree.Project));
    Assert(catalog.LastNewCount==0 && catalog.LastReusedCount==14,"Third project reuses existing physical probes");
    catalog.Complete();
}
using(var db=new SqliteConnection($"Data Source={threeDb};Pooling=False")) {
    db.Open();using var cmd=db.CreateCommand();cmd.CommandText="SELECT count(*) FROM basic_blocks";
    Assert(Convert.ToInt32(cmd.ExecuteScalar())==16,"Three projects retain 16 unique probes");
    cmd.CommandText="SELECT count(*) FROM legacy_probe_variants";
    Assert(Convert.ToInt32(cmd.ExecuteScalar())==44,"Three projects record individual provenance");
}
const string emptyFirstSource="class ConditionalEmpty {\n#if DIFFERENT\nvoid M(int x) { if(x==1) return; System.Console.WriteLine(x); }\n#endif\n}";
var emptyPath=Path.Combine(directory,"ConditionalEmpty.cs");File.WriteAllText(emptyPath,emptyFirstSource);
var emptyFirst=Document("ConditionalEmptyFirst",emptyFirstSource,emptyPath);
var populatedSecond=Document("ConditionalEmptySecond",emptyFirstSource,emptyPath);
populatedSecond=populatedSecond.Project.WithParseOptions(new CSharpParseOptions(preprocessorSymbols:new[]{"DIFFERENT"})).GetDocument(populatedSecond.Id)!;
var emptyDb=Path.Combine(directory,"union-empty-first.sqlite");
using(var catalog=new ContextCatalog(emptyDb,"net8.0","Debug")) {
    await catalog.AnalyzeDocument(emptyFirst,catalog.AddProject(emptyFirst.Project));
    Assert(catalog.LastNewCount==0,"First shared projection is empty");
    await catalog.AnalyzeDocument(populatedSecond,catalog.AddProject(populatedSecond.Project));
    Assert(catalog.LastNewCount>0 && catalog.LastReusedCount==0,"Second projection adds points after empty first");
    catalog.Complete();
}
string solutionPath=Path.Combine(directory,"options.sln");File.WriteAllText(solutionPath,"");
var cli=AnalyzerOptions.Parse(new[]{solutionPath,"net8.0",directory,"Release","-","M:C.A","x64","--platform","AnyCPU","--include-project","A.csproj","--exclude-project","A.csproj"});
Assert(cli.Configuration=="Release" && cli.Platform=="AnyCPU" && cli.Roots.Single()=="M:C.A","CLI positional compatibility and named platform");
var filterProject=document.Project.Solution.WithProjectFilePath(document.Project.Id,Path.Combine(directory,"A.csproj")).GetProject(document.Project.Id)!;
Assert(!cli.Includes(filterProject),"Exclusion takes precedence over inclusion");
Throws<ArgumentException>(()=>AnalyzerOptions.Parse(new[]{solutionPath,"net8.0",directory,"Debug","graph.json"}),"Graphify envelope accepted");
string stability=Path.Combine(directory,"stability.sqlite");if(File.Exists(stability))File.Delete(stability);
using(var catalog=new ContextCatalog(stability,"net8.0","Debug")) {
    catalog.AddProject(sharedOne.Project); // Change numeric variant numbering deliberately.
    await catalog.AnalyzeDocument(document,catalog.AddProject(document.Project));catalog.Complete();
}
string StableKey(string dbPath) {
    using var db=new SqliteConnection($"Data Source={dbPath};Pooling=False");db.Open();using var cmd=db.CreateCommand();cmd.CommandText="SELECT stable_key FROM methods WHERE signature='Sample.A(int)'";return (string)cmd.ExecuteScalar()!;
}
Assert(StableKey(path)==StableKey(stability),"Stable method identity independent of numeric variant numbering");
var input=new InputRegistry();string inputPath=Path.Combine(directory,"changing.txt");File.WriteAllText(inputPath,"before");input.Track(inputPath);File.WriteAllText(inputPath,"after");Throws<InvalidOperationException>(()=>input.Verify(),"Changed input accepted");
using(var catalog=new ContextCatalog(Path.Combine(directory,Guid.NewGuid()+".sqlite"),"net8.0","Debug")) {
    var cancelled=new CancellationToken(true);
    try {await catalog.AnalyzeDocument(document,catalog.AddProject(document.Project),token:cancelled);throw new Exception("Cancellation ignored");}catch(OperationCanceledException){assertions++;}
}
await TraceSelectionTests.Run(directory,references,Assert);
await InterestFilterTests.Run(directory,references,Assert);
using(var resourcesTest=new TraceSelectionModel(unionForward,new SelectionResources(new TraceSelectionOptions(),CancellationToken.None),512)) {
    resourcesTest.Load();
    Assert(resourcesTest.Protected.Values.Count(reason=>reason=="variant_without_selection")==2,"Shared union-exclusive IDs are protected before selection");
}
{
    var limits=new TraceSelectionOptions();var resources=new SelectionResources(limits,CancellationToken.None){PhaseFraction=1};
    var interest=ApplicationInterestFilter.Select(unionForward,limits,new HashSet<long>(),resources.Check,resources.Reserve,resources.Release);
    Assert(interest.Enabled.Count==16,"Second filter preserves shared-variant integrity even when count target is lower");
}
string published=Path.Combine(directory,"published.sqlite");File.Copy(path,published,true);
string bad=Path.Combine(directory,"bad.sqlite");File.WriteAllText(bad,"invalid");Throws<SqliteException>(()=>CatalogPublication.Publish(bad,published),"Invalid catalog published");
using(var staging=new CatalogStaging(directory)){File.Copy(path,staging.Path);CatalogPublication.Publish(staging.Path,published);Assert(File.Exists(published+".previous"),"Previous generation retained");}
// Benchmark uses one workspace/semantic model for each pair, and no MSBuild target pipeline.
var benchmarks=new List<object>();long previousRows=0;
foreach(int size in new[]{100,200,400}) {
    var text=new StringBuilder("class Bench {");
    for(int n=0;n<size;n++)text.Append($"public int M{n}(int x) {{ while(x>2) x--; if(x==1) return x; return M{(n+1)%size}(x); }}");
    text.Append('}');var bench=Document("Bench"+size,text.ToString());
    var benchRoot=await bench.GetSyntaxRootAsync();var benchModel=await bench.GetSemanticModelAsync();
    var clock=Stopwatch.StartNew();var baseline=new BlockExtractor().ExtractBlocks(benchModel!,benchRoot!);double legacyMs=clock.Elapsed.TotalMilliseconds;
    string benchPath=Path.Combine(directory,"bench-"+size+".sqlite");if(File.Exists(benchPath))File.Delete(benchPath);
    clock.Restart();long graphs;
    using(var catalog=new ContextCatalog(benchPath,"net8.0","Debug")) {
        var actual=await catalog.AnalyzeDocument(bench,catalog.AddProject(bench.Project));Assert(actual.Count==baseline.Count,"Benchmark legacy parity");
        catalog.Complete();graphs=catalog.GraphsCreated;Assert(graphs==size,"Benchmark CFG reuse");
    }
    double fullMs=clock.Elapsed.TotalMilliseconds;long rows;
    using(var db=new SqliteConnection($"Data Source={benchPath};Pooling=False")){db.Open();using var cmd=db.CreateCommand();cmd.CommandText="SELECT (SELECT count(*) FROM flow_nodes)+(SELECT count(*) FROM flow_points)+(SELECT count(*) FROM flow_edges)+(SELECT count(*) FROM call_sites)+(SELECT count(*) FROM call_targets)";rows=Convert.ToInt64(cmd.ExecuteScalar());}
    clock.Restart();var selection=TraceSelectionEngine.Select(benchPath,new TraceSelectionOptions {SamplesPerRoot=64,MaxDurationSeconds=30});
    var selectionMs=clock.Elapsed.TotalMilliseconds;
    Assert(selection.PeakBufferBytes<=512L*1024*1024,"Growing cyclic fixture stays inside selection memory limit");
    Assert(selection.Status!="fallback"||selection.FallbackReason=="no_qualified_contexts"&&selection.Disabled.Count==0&&selection.Roots.All(root=>root.Status!="qualified"),
        "Cyclic fixture may retain baseline when no root qualifies; other fallbacks fail the benchmark");
    benchmarks.Add(new {methods=size,legacy_ms=legacyMs,context_ms=fullMs,graphs,legacy_probes=baseline.Count,graph_rows=rows,database_bytes=new FileInfo(benchPath).Length,
        selection_ms=selectionMs,selection_disabled=selection.Disabled.Count,selection_roots=selection.Roots.Count,selection_peak_buffer_bytes=selection.PeakBufferBytes,
        selection_fit=selection.Summary});
    Assert(rows<100L*size,"No quadratic materialization");
    if(previousRows!=0)Assert(rows==previousRows*2,"Doubling fixture doubles graph rows");
    previousRows=rows;
}
await ApplicationTests.Run(directory,references,Assert);
var report=JsonSerializer.Serialize(new {assertions,benchmarks,peak_working_set_bytes=Process.GetCurrentProcess().PeakWorkingSet64},new JsonSerializerOptions {WriteIndented=true});
File.WriteAllText(Path.Combine(directory,"benchmark.json"),report);Console.WriteLine(report);
if(export==null)Directory.Delete(directory,true);
else Console.WriteLine("Fixture exported to "+directory);
