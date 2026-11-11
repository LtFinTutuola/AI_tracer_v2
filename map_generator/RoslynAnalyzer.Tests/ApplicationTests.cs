using System.Collections;
using System.Reflection;
using System.Runtime.Loader;
using System.Text.Json;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;
using Microsoft.Data.Sqlite;
using RoslynAnalyzer;

internal static class ApplicationTests
{
    public static async System.Threading.Tasks.Task Run(string directory,MetadataReference[] references,Action<bool,string> assert)
    {
        const string source="""
        using System; using System.Threading.Tasks; using System.Collections.Generic;
        public static class TechnicalHelpers {
          public static int CompareTo(int a,int b) { return a.CompareTo(b); }
          public static int AssignFieldValue(int n) { int count=0; for(int i=0;i<n;i++) { if(i%3!=0) { continue; } count++; } return count; }
          public static void Cache(int n) { for(int i=0;i<n;i++) { var x=CompareTo(i,n); } }
        }
        public class BaseFixture { public int BaseValue; public BaseFixture(int value) { BaseValue=value; } }
        public class Tracker : IDisposable { public void Dispose() { ApplicationFixture.Effects+=10; } }
        public class KeyData { public bool Allowed; public bool IsAllowed(object owner,object transaction,out string errorMessage) { errorMessage="";return Allowed; } }
        public class ApplicationFixture : BaseFixture {
          public static int Effects; public int Status; public static event Action Tick;
          public ApplicationFixture() : base(3) { Status=0; }
          public ApplicationFixture(int value) : base(value) => Status=value;
          public int Start(int n,bool allowed,int choice) {
            try {
              TechnicalHelpers.Cache(n); int count=TechnicalHelpers.AssignFieldValue(n);
              if(!allowed) return -1;
              if(choice==7) if(n>0) Effects++; // nested dangling-if needs two explicit false arms
              switch(choice) { case 0: Status=1; return count; case 1: Pay(); return 5; case 2: throw new InvalidOperationException("expected"); default: return 9; }
            } finally { Effects+=100; }
          }
          public void Pay() { Effects++; }
          public void BoundaryCaller(bool flag) { Console.WriteLine(flag ? First() : Second()); }
          private int First() { Effects+=1;return 1; }
          private int Second() { Effects+=2;return 2; }
          public int BranchCases(bool login,bool cancel,bool allowed) {
            int result=0;var key=new KeyData { Allowed=allowed };object CurrentTransaction=null;
            if(!login && !cancel) result+=1;
            if(login || cancel) result+=2;
            if(!key.IsAllowed(this, CurrentTransaction, out var errorMessage)) result+=4;
            if(!(login && cancel)) { } else { result+=8; }
            if((login || cancel) && allowed) result+=16;
            return result;
          }
          public int Expression(int x) => x+1;
          public async Task<int> WorkAsync() { await Task.Yield(); return 7; }
          public Task<int> ReturnTask() => Task.FromResult(8);
          public ref int RefStatus() { return ref Status; }
          public int UseRef() { ref int value=ref RefStatus(); value=12; return Status; }
          public T Identity<T>(T value) => value;
          public int Resource(bool fail) { using var resource=new Tracker(); return fail ? throw new InvalidOperationException("resource") : 42; }
          public IEnumerable<int> Iterator() { yield return 1; }
          public void Register() { Tick += () => Pay(); Task.Run(() => Pay()); new int[1].GetEnumerator(); }
          public void RegisterTechnical() { Tick += () => TechnicalHelpers.Cache(100); }
          public int Early(int n) { while(n>0) { if(n==2) break; n--; } return n; }
        }
        """;
        string path=Path.Combine(directory,"ApplicationFixture.cs");File.WriteAllText(path,source);
        string policyPath=Path.Combine(directory,"application-profile.json");
        var policy=new {version=1,name="application-test",application_assemblies=new[]{"ApplicationFixture"},rules=new object[]{
            new {type="TechnicalHelpers",role="technical"},new {type="ApplicationFixture",member="Start",role="operation"},
            new {type="ApplicationFixture",member="Pay",role="operation"},new {type="ApplicationFixture",member="Expression",role="operation"},
            new {type="ApplicationFixture",member="BranchCases",role="operation"},
            new {type="System.Console",member="WriteLine",role="opaque"},
            new {type="ApplicationFixture",member="WorkAsync",role="operation"},new {type="ApplicationFixture",member="ReturnTask",role="operation"},
            new {type="ApplicationFixture",member=".ctor",role="operation"},new {type="ApplicationFixture",member="RefStatus",role="operation"},
            new {type="BaseFixture",member=".ctor",role="operation"},
            new {type="ApplicationFixture",member="Identity",role="operation"},new {type="ApplicationFixture",member="Resource",role="operation"},
            new {type="ApplicationFixture",member="Iterator",role="opaque"},new {type="ApplicationFixture",member="Status",role="state_assignment"}}};
        File.WriteAllText(policyPath,JsonSerializer.Serialize(policy));
        var options=new TraceSelectionOptions {Mode="application",ObservationPolicy=policyPath,AmbiguityBudget=0,MaxDurationSeconds=120};
        using var workspace=new AdhocWorkspace();
        var document=workspace.AddProject("ApplicationFixture",LanguageNames.CSharp).WithCompilationOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)).AddMetadataReferences(references)
            .AddDocument("ApplicationFixture.cs",SourceText.From(source),filePath:path);
        string catalogPath=Path.Combine(directory,"application.sqlite");if(File.Exists(catalogPath))File.Delete(catalogPath);
        using(var catalog=new ContextCatalog(catalogPath,"net8.0","Debug")) {
            await catalog.AnalyzeDocument(document,catalog.AddProject(document.Project));catalog.Complete(finalize:false);
            assert(catalog.GraphsCreated==catalog.CfgRequests,"Application facts reuse the existing CFG pass");
        }
        var first=TraceSelectionEngine.Select(catalogPath,options);var second=TraceSelectionEngine.Select(catalogPath,options);
        assert(first.Application!=null&&first.Disabled.SetEquals(second.Disabled)&&first.Application.Enabled.SetEquals(second.Application!.Enabled),"Application decisions repeat exactly");
        assert(first.FirstLevel==null&&first.Interest==null,"Application mode bypasses both previous selectors");
        assert(first.Application!.NewProbes.Count>0&&first.Application.Enabled.Count>0,"Application boundaries add stable numeric probes");
        assert(first.Application.Observations.Values.Any(o=>o.Kind=="decision")&&first.Application.Observations.Values.Any(o=>o.Kind=="state_assignment_completed"),"Decision alternatives and completed state assignments are obligations");
        using(var db=new SqliteConnection($"Data Source={catalogPath};Pooling=False")) {
            db.Open();using var c=db.CreateCommand();c.CommandText="CREATE TRIGGER app_failure BEFORE INSERT ON application_observations BEGIN SELECT RAISE(ABORT,'test rollback'); END";c.ExecuteNonQuery();
        }
        bool rollback=false;try{TraceSelectionStore.Apply(catalogPath,options,first);}catch(SqliteException){rollback=true;}
        using(var db=new SqliteConnection($"Data Source={catalogPath};Pooling=False")) {
            db.Open();using var c=db.CreateCommand();c.CommandText="SELECT (SELECT count(*) FROM basic_blocks)+(SELECT count(*) FROM application_placements)+(SELECT count(*) FROM trace_selection_profiles)";
            assert(rollback&&Convert.ToInt32(c.ExecuteScalar())==first.Application.ExistingProbes,"New IDs, placements and decisions roll back atomically");
            c.CommandText="DROP TRIGGER app_failure";c.ExecuteNonQuery();
        }
        string profile=TraceSelectionStore.Apply(catalogPath,options,first);TraceSelectionStore.VerifyIntegrity(catalogPath);
        var again=TraceSelectionEngine.Select(catalogPath,options);
        assert(again.Application!.NewProbes.Count==0&&again.Application.Enabled.SetEquals(first.Application.Enabled),"Reselection reuses appended IDs");
        assert(TraceSelectionStore.Apply(catalogPath,options,again)==profile,"Profile identity survives requalification");
        string originalPolicy=File.ReadAllText(policyPath);
        File.WriteAllText(policyPath,originalPolicy.Replace("\"Expression\"","\"NotAnOperation\""));
        var less=TraceSelectionEngine.Select(catalogPath,options);TraceSelectionStore.Apply(catalogPath,options,less);
        assert(less.Application!.Enabled.Count<again.Application.Enabled.Count,"Policy can remove an operation without deleting its numeric IDs");
        File.WriteAllText(policyPath,originalPolicy);
        var restored=TraceSelectionEngine.Select(catalogPath,options);
        assert(restored.Application!.NewProbes.Count==0&&restored.Application.Enabled.SetEquals(again.Application.Enabled),"Disabled application boundaries retain placements and can be re-enabled with the same IDs");
        TraceSelectionStore.Apply(catalogPath,options,restored);
        using(var db=new SqliteConnection($"Data Source={catalogPath};Pooling=False")) {
            db.Open();using var cmd=db.CreateCommand();cmd.CommandText="SELECT count(*) FROM basic_blocks WHERE method_signature LIKE '%TechnicalHelpers.%' AND to_trace=1";
            assert(Convert.ToInt64(cmd.ExecuteScalar())==0,"Technical helpers have no enabled application probes");
            cmd.CommandText="SELECT count(*) FROM application_entries WHERE reasons LIKE '%callback%' OR reasons LIKE '%event%'";
            assert(Convert.ToInt64(cmd.ExecuteScalar())>=1,"Registered callback entries are inventoried");
            cmd.CommandText="SELECT count(*) FROM application_placements p JOIN basic_blocks b ON b.id=p.legacy_id WHERE b.method_signature LIKE '%lambda%'";
            assert(Convert.ToInt64(cmd.ExecuteScalar())==0,"Callback discovery alone never creates generic boundary probes");
            cmd.CommandText="SELECT count(*) FROM legacy_block_links l JOIN basic_blocks b ON b.id=l.legacy_id WHERE b.method_signature LIKE '%CompareTo%' AND l.point_id IS NOT NULL";
            assert(Convert.ToInt64(cmd.ExecuteScalar())>0,"Simple return expression fallback has a precise CFG location");
            cmd.CommandText="SELECT count(*) FROM flow_edges WHERE semantics IN ('Break','Continue')";
            assert(Convert.ToInt64(cmd.ExecuteScalar())>=2,"Guard break/continue probes use the actual CFG successor edges");
            cmd.CommandText="SELECT count(*) FROM legacy_probe_variants v JOIN basic_blocks b ON b.id=v.legacy_id WHERE b.reason LIKE 'Application observation:%'";
            assert(Convert.ToInt64(cmd.ExecuteScalar())==0,"Application bindings do not rewrite legacy selection provenance");
            foreach(var regression in new[]{("!login && !cancel / false",2),("login || cancel / true",2),("!key.IsAllowed(this, CurrentTransaction, out var errorMessage) / false",1)}) {
                cmd.CommandText="SELECT count(*) FROM application_locations l JOIN application_observations o ON o.id=l.observation_id JOIN methods m ON m.id=o.method_id WHERE m.signature LIKE '%BranchCases%' AND o.evidence=@label";
                cmd.Parameters.Clear();cmd.Parameters.AddWithValue("@label",regression.Item1);
                assert(Convert.ToInt64(cmd.ExecuteScalar())==regression.Item2,"Semantic frontier for production regression: "+regression.Item1);
            }
            cmd.Parameters.Clear();cmd.CommandText="SELECT count(*) FROM application_observations o JOIN methods m ON m.id=o.method_id WHERE m.signature LIKE '%BranchCases%' AND o.kind='decision' AND o.mapping_status<>'exact_frontier'";
            assert(Convert.ToInt64(cmd.ExecuteScalar())==0,"Negation, nested short circuit and empty arms have demonstrated frontiers");
            cmd.CommandText="SELECT count(*) FROM application_observations o JOIN methods m ON m.id=o.method_id JOIN application_locations l ON l.observation_id=o.id WHERE m.signature LIKE '%BoundaryCaller%' AND o.kind='operation_call' AND EXISTS(SELECT 1 FROM flow_points p WHERE p.node_id=l.node_id AND p.kind='control' AND p.position>l.position)";
            assert(Convert.ToInt64(cmd.ExecuteScalar())==1,"Call boundary precedes lowered conditional argument evaluation");
        }
        var engine=new Engine();var task=new AITracer.MsBuildTask.InjectTracesTask {BuildEngine=engine,DatabasePath=catalogPath,Compile=new ITaskItem[]{new TaskItem(path)},IntermediateOutputPath=Path.Combine(directory,"application-injection")};
        assert(task.Execute()&&engine.Errors.Count==0,"Application injection succeeds: "+string.Join(";",engine.Errors));
        assert(File.Exists(task.ProfileManifest),"Build emits a matching profile manifest");
        File.Copy(task.ProfileManifest,Path.Combine(directory,"application.profile.json"),true);
        string generated=File.ReadAllText(task.ModifiedCompile.Single().ItemSpec);
        var original=Compile(source,"OriginalApplication");var instrumented=Compile(generated,"InstrumentedApplication");
        Assembly Compile(string code,string name) {
            var runtime=CSharpSyntaxTree.ParseText("namespace AITracer.Runtime { public static class TraceContext { public static System.Collections.Generic.List<int> Events=new(); public static void Log(int id) { Events.Add(id); } } }");
            var c=CSharpCompilation.Create(name,new[]{CSharpSyntaxTree.ParseText(code),runtime},references,new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
            using var stream=new MemoryStream();var emit=c.Emit(stream);assert(emit.Success,"Application-generated source compiles: "+string.Join(";",emit.Diagnostics.Where(d=>d.Severity==DiagnosticSeverity.Error)));
            stream.Position=0;return AssemblyLoadContext.Default.LoadFromStream(stream);
        }
        var type=instrumented.GetType("ApplicationFixture")!;object instance=Activator.CreateInstance(type)!;
        IList events=(IList)instrumented.GetType("AITracer.Runtime.TraceContext")!.GetField("Events")!.GetValue(null)!;
        File.WriteAllLines(Path.Combine(directory,"application-constructors.log"),events.Cast<int>().Select(id=>$"2026-11-09T10:00:00Z||constructors||1||{id}"));
        int branchIndex=0;
        foreach(bool login in new[]{false,true})foreach(bool cancel in new[]{false,true})foreach(bool allowed in new[]{false,true}) {
            events.Clear();int expected=(!login&&!cancel?1:0)+(login||cancel?2:0)+(!allowed?4:0)+(login&&cancel?8:0)+((login||cancel)&&allowed?16:0);
            assert((int)type.GetMethod("BranchCases")!.Invoke(instance,new object[]{login,cancel,allowed})! ==expected,"Boolean frontier injection preserves results");
            File.WriteAllLines(Path.Combine(directory,"application-branches-"+branchIndex+++".log"),events.Cast<int>().Select(id=>$"2026-11-09T10:00:00Z||branches||1||{id}"));
        }
        int[] Run(int n,bool allowed,int choice,out int? result,out string? error) {
            events.Clear();result=null;error=null;try{result=(int)type.GetMethod("Start")!.Invoke(instance,new object[]{n,allowed,choice})!;}catch(TargetInvocationException ex){error=ex.InnerException!.Message;}
            return events.Cast<int>().ToArray();
        }
        var counts=new List<object>();int? expectedCount=null;
        foreach(int n in new[]{10,1000,100000}) {
            var word=Run(n,true,0,out int? value,out string? error);
            assert(value==(n+2)/3&&error==null,"Filtering preserves calculation result for "+n);
            expectedCount??=word.Length;assert(word.Length==expectedCount,"Technical loop size does not multiply application events");
            counts.Add(new {iterations=n,events=word.Length});
        }
        var allowedWord=Run(10,true,1,out _,out _);var rejectedWord=Run(10,false,1,out _,out _);var failedWord=Run(10,true,2,out _,out var failure);
        assert(!allowedWord.SequenceEqual(rejectedWord)&&!allowedWord.SequenceEqual(failedWord)&&!rejectedWord.SequenceEqual(failedWord),"Allowed, denied and failed application observations remain distinguishable");
        assert(failure=="expected","Escaping exception is preserved");
        foreach(int choice in new[]{0,1,2,7}) {
            var beforeType=original.GetType("ApplicationFixture")!;var before=Activator.CreateInstance(beforeType)!;
            beforeType.GetField("Effects")!.SetValue(null,0);type.GetField("Effects")!.SetValue(null,0);
            object? a=null,b=null;string? ae=null,be=null;
            try{a=beforeType.GetMethod("Start")!.Invoke(before,new object[]{10,true,choice});}catch(TargetInvocationException ex){ae=ex.InnerException!.GetType().FullName;}
            try{b=type.GetMethod("Start")!.Invoke(instance,new object[]{10,true,choice});}catch(TargetInvocationException ex){be=ex.InnerException!.GetType().FullName;}
            assert(Equals(a,b)&&ae==be&&Equals(beforeType.GetField("Effects")!.GetValue(null),type.GetField("Effects")!.GetValue(null)),"Results, exceptions, nesting and finally effects preserved for "+choice);
        }
        var asyncValue=(System.Threading.Tasks.Task<int>)type.GetMethod("WorkAsync")!.Invoke(instance,null)!;
        assert(await asyncValue==7,"Async operation preserves awaited return");
        assert((int)type.GetMethod("Expression")!.Invoke(instance,new object[]{3})! ==4,"Expression-bodied method is expanded correctly");
        assert(await (System.Threading.Tasks.Task<int>)type.GetMethod("ReturnTask")!.Invoke(instance,null)! ==8,"Returning a task handle preserves the handle semantics");
        assert((int)type.GetField("BaseValue")!.GetValue(instance)! ==3,"Constructor base initializer is preserved");
        var other=Activator.CreateInstance(type,new object[]{9})!;
        assert((int)type.GetField("Status")!.GetValue(other)! ==9,"Expression constructor preserves its initializer and assignment");
        assert((int)type.GetMethod("UseRef")!.Invoke(instance,null)! ==12,"Ref return identity and mutations are preserved");
        assert((int)type.GetMethod("Identity")!.MakeGenericMethod(typeof(int)).Invoke(instance,new object[]{13})! ==13,"Generic expression return remains target typed");
        type.GetField("Effects")!.SetValue(null,0);assert((int)type.GetMethod("Resource")!.Invoke(instance,new object[]{false})! ==42&&(int)type.GetField("Effects")!.GetValue(null)! ==10,"Using declaration is disposed before leaving the operation");
        int index=0;foreach(var word in new[]{allowedWord,rejectedWord,failedWord}) {
            File.WriteAllLines(Path.Combine(directory,"application-events-"+index+++".log"),word.Select((id,n)=>$"2026-11-09T10:00:00.{n:D7}Z||fixture||1||{id}"));
        }
        File.WriteAllText(Path.Combine(directory,"application-benchmark.json"),JsonSerializer.Serialize(new {counts,profile,summary=again.Application.Summary},new JsonSerializerOptions {WriteIndented=true}));
        bool changed=false;File.WriteAllText(path,source+" // changed");try{TraceSelectionEngine.Select(catalogPath,options);}catch(InvalidOperationException){changed=true;}finally{File.WriteAllText(path,source);}
        assert(changed,"Application requalification rejects changed sources");
        var cancelled=new CancellationToken(true);bool cancellation=false;try{TraceSelectionEngine.Select(catalogPath,options,cancelled);}catch(OperationCanceledException){cancellation=true;}
        assert(cancellation,"Application cancellation never falls back to all probes");
        bool quota=false;try{TraceSelectionEngine.Select(catalogPath,options with {MaxMemoryMb=1});}catch(SelectionMemoryException){quota=true;}
        assert(quota,"Application memory exhaustion prevents an unverified profile");
        bool deadline=false;try{TraceSelectionEngine.Select(catalogPath,options with {MaxDurationSeconds=.000001});}catch(SelectionDeadlineException){deadline=true;}
        assert(deadline,"Application deadline cannot publish an all-probes fallback");
        using(var db=new SqliteConnection($"Data Source={catalogPath};Pooling=False")) {
            db.Open();using var c=db.CreateCommand();c.CommandText="UPDATE basic_blocks SET to_trace=0 WHERE id=(SELECT legacy_id FROM application_placements WHERE kind='operation_error' LIMIT 1)";c.ExecuteNonQuery();
        }
        var invalidEngine=new Engine();var invalidTask=new AITracer.MsBuildTask.InjectTracesTask {BuildEngine=invalidEngine,DatabasePath=catalogPath,Compile=new ITaskItem[]{new TaskItem(path)},IntermediateOutputPath=Path.Combine(directory,"invalid-app-injection")};
        assert(!invalidTask.Execute()&&invalidEngine.Errors.Count>0,"Injector rejects flags changed outside the verified application profile");
        TraceSelectionStore.Apply(catalogPath,options,again);

        // Exact policy precedence and overlapping selector conflicts are checked
        // against symbol identities rather than source spelling.
        var descriptor=new ApplicationSymbol("symbol","App","N","N.Type","Run","M:N.Type.Run","Method",new[]{"Contract"});
        var precedence=new ApplicationPolicy {Rules=new[]{new ApplicationRule {Assembly="App",Role="technical"},new ApplicationRule {Type="N.Type",Member="Run",Role="operation"}}};
        assert(precedence.Role(descriptor)=="operation","Member semantics override a technical assembly");
        var conflict=new ApplicationPolicy {Rules=new[]{new ApplicationRule {Type="N.Type",Role="technical"},new ApplicationRule {Contract="Contract",Role="operation"}}};
        bool contradictory=false;try{conflict.Role(descriptor);}catch(InvalidOperationException){contradictory=true;}
        assert(contradictory,"Equal-specificity contradictions are rejected");
        await SharedVariants();

        async System.Threading.Tasks.Task SharedVariants() {
            string sharedPath=Path.Combine(directory,"SharedApplication.cs"),sharedDb=Path.Combine(directory,"application-variants.sqlite"),sharedPolicy=Path.Combine(directory,"application-variants-policy.json");
            string sharedSource="public class SharedApplication { public int Run(bool x) { if(x) return 1; return 2; } }";File.WriteAllText(sharedPath,sharedSource);
            File.WriteAllText(sharedPolicy,JsonSerializer.Serialize(new {version=1,name="shared-app",rules=new[]{new {type="SharedApplication",member="Run",role="operation"}}}));
            using(var catalog=new ContextCatalog(sharedDb,"net8.0","Debug")) {
                foreach(string variant in new[]{"VariantA","VariantB"}) {
                    var d=workspace.AddProject(variant,LanguageNames.CSharp).WithCompilationOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)).AddMetadataReferences(references).AddDocument("SharedApplication.cs",SourceText.From(sharedSource),filePath:sharedPath);
                    await catalog.AnalyzeDocument(d,catalog.AddProject(d.Project));
                }
                catalog.Complete(finalize:false);
            }
            var o=options with {ObservationPolicy=sharedPolicy};var r=TraceSelectionEngine.Select(sharedDb,o);
            assert(r.Application!.SharedAmbiguities>0,"Shared IDs retain variant ambiguity explicitly");
            TraceSelectionStore.Apply(sharedDb,o,r);
            var e=new Engine();var inject=new AITracer.MsBuildTask.InjectTracesTask {BuildEngine=e,DatabasePath=sharedDb,Compile=new ITaskItem[]{new TaskItem(sharedPath)},IntermediateOutputPath=Path.Combine(directory,"shared-application-injection")};
            assert(inject.Execute()&&e.Errors.Count==0,"Shared variant boundaries inject once per physical anchor");
            var asm=Compile(File.ReadAllText(inject.ModifiedCompile.Single().ItemSpec),"SharedApplicationInjected");
            var t=asm.GetType("SharedApplication")!;object value=Activator.CreateInstance(t)!;var words=(IList)asm.GetType("AITracer.Runtime.TraceContext")!.GetField("Events")!.GetValue(null)!;
            assert((int)t.GetMethod("Run")!.Invoke(value,new object[]{true})! ==1,"Shared injection remains compilable and equivalent");
            File.WriteAllLines(Path.Combine(directory,"application-variants.log"),words.Cast<int>().Select(id=>$"2026-11-09T10:00:00Z||shared||1||{id}"));
            File.Copy(inject.ProfileManifest,Path.Combine(directory,"application-variants.profile.json"),true);
        }
    }
    internal sealed class Engine:IBuildEngine {
        public List<string> Errors {get;}=new();public bool ContinueOnError=>false;public int LineNumberOfTaskNode=>0;public int ColumnNumberOfTaskNode=>0;public string ProjectFileOfTaskNode=>"test";
        public void LogErrorEvent(BuildErrorEventArgs e)=>Errors.Add(e.Message??"");public void LogWarningEvent(BuildWarningEventArgs e){}public void LogMessageEvent(BuildMessageEventArgs e){}public void LogCustomEvent(CustomBuildEventArgs e){}
        public bool BuildProjectFile(string file,string[] targets,IDictionary globals,IDictionary outputs)=>true;
    }
}
