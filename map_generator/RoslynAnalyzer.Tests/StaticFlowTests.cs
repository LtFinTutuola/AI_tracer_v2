using System.Collections;
using System.Reflection;
using System.Runtime.Loader;
using System.Text;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;
using Microsoft.Data.Sqlite;
using RoslynAnalyzer;

internal static class StaticFlowTests
{
    internal static async System.Threading.Tasks.Task Run(string directory,MetadataReference[] references,Action<bool,string> assert)
    {
        directory=Path.Combine(directory,"static-flow");Directory.CreateDirectory(directory);
        assert(StaticFlowPlan.IsBlindEdit(new("x",0,0,"{\n#line hidden\nAITracer.Runtime.TraceContext.Log(12);\n#line default\n}",0,12)),"Blind grammar accepts constant emissions");
        foreach(string text in new[]{"if(x) AITracer.Runtime.TraceContext.Log(12);","AITracer.Runtime.TraceContext.Log(x);","counter++;","try {} finally {}"})
            assert(!StaticFlowPlan.IsBlindEdit(new("x",0,0,text,0,12)),"Blind grammar rejects runtime logic: "+text);
        var arcs=new Dictionary<long,long[]>{{1,new long[]{2,3}},{2,new long[]{3}},{3,Array.Empty<long>()},{4,new long[]{5}},{5,new long[]{4}}};
        var scc=StaticFlowModel.Scc(arcs.Keys,n=>arcs[n],()=>{});
        assert(scc.Count==4&&scc.Any(c=>c.SequenceEqual(new long[]{4,5})),"SCC decomposition handles cross edges and mutual recursion");
        const string source="""
          public class StaticFixture {
            public int State;
            public int Branch(bool x) { if(x) { State=1; } else { State=2; } return State; }
            public void Helper(int n) { if(n>0) State++; else State--; }
            public int Loop(int n) { for(int i=0;i<n;i++) { Helper(i); } return State; }
            public void Recursive(int n) { if(n>0) Recursive(n-1); State++; }
            public void MutualA(int n) { if(n>0) MutualB(n-1); }
            public void MutualB(int n) { if(n>0) MutualA(n-1); }
            public void Root(int n) { Recursive(n); MutualA(n); }
            public void Twice() { Branch(true); Branch(false); }
            public void TechnicalCaller() { Branch(true); }
            public void Outside() { TechnicalCaller(); }
            public int External(bool x) { int n=System.Math.Abs(State); if(x) { State=n+1; } else { State=n-1; } return State; }
            public void UsesExternal(bool x) { External(x); if(x) { State++; } else { State--; } }
            public void Dispatch(IWorker worker,bool x) { worker.Work(x); if(x) { State++; } else { State--; } }
            public event System.Action<bool> Changed;
            public void Subscribe() { Changed += Callback; }
            public void Publish(bool x) { Changed(x); if(x) { State++; } else { State--; } }
            public void Callback(bool x) { if(x) { State=10; } else { State=20; } }
            public void InvokeDelegate(System.Action<bool> handler,bool x) { handler(x); if(x) { State++; } else { State--; } }
            public void Exceptional(bool x) { try { External(x); } finally { State++; } }
          }
          public interface IWorker { void Work(bool x); }
          public class WorkerA : IWorker { public void Work(bool x) { if(x) { Value=1; } else { Value=2; } } public int Value; }
          public class WorkerB : IWorker { public void Work(bool x) { if(x) { Value=3; } else { Value=4; } } public int Value; }
          """;
        var deep=new StringBuilder(source+" public class Deep {");
        for(int i=0;i<40;i++)deep.Append("public void M"+i+"(){"+(i==39?"":"M"+(i+1)+"();")+"}");
        deep.Append('}');string code=deep.ToString(),file=Path.Combine(directory,"StaticFixture.cs"),path=Path.Combine(directory,"fixture.sqlite");
        File.WriteAllText(file,code);
        using var workspace=new AdhocWorkspace();
        var document=workspace.AddProject("StaticFixture",LanguageNames.CSharp).WithCompilationOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)).AddMetadataReferences(references).AddDocument("Fixture.cs",SourceText.From(code),filePath:file);
        using(var catalog=new ContextCatalog(path,"net8.0","Debug")){await catalog.AnalyzeDocument(document,catalog.AddProject(document.Project));catalog.Complete(finalize:false);}
        var options=new TraceSelectionOptions {Mode="static",AmbiguityBudget=0,MaxCallDepth=0,MaxFlowStates=200000,MaxDurationSeconds=120};
        var result=TraceSelectionEngine.Select(path,options);var plan=result.Static!;
        assert(plan!=null&&result.Application!.Edits.All(StaticFlowPlan.IsBlindEdit),"Milestone 1: static plan contains only blind edits");
        var names=new Dictionary<long,string>();
        using(var db=new SqliteConnection($"Data Source={path};Pooling=False")){db.Open();using var c=db.CreateCommand();c.CommandText="SELECT id,signature FROM methods";using var r=c.ExecuteReader();while(r.Read())names[r.GetInt64(0)]=r.GetString(1);}
        long Method(string text)=>names.Single(p=>p.Value.Contains(text,StringComparison.Ordinal)).Key;
        assert(plan.Regions.Any(r=>r.Kind=="loop")&&plan.Regions.Count(r=>r.Kind=="recursion")==2,"Milestone 2: loops, direct and indirect recursion catalogued");
        assert(plan.Methods.Single(m=>m.Method==Method(".Helper(")).Repeated,"Milestone 3: helper repetition propagates through loop call sites");
        assert(plan.Methods.Single(m=>m.Method==Method(".M0(")).Status=="qualified_normal_flow","Forty-level chain qualifies even with MaxCallDepth=0");
        long branch=Method(".Branch(");assert(plan.Witnesses[branch].Length==2,"Branch has two normal-path signatures");
        foreach(string name in new[]{".External(",".UsesExternal(",".Dispatch(",".Publish(",".InvokeDelegate("}) {
            long id=Method(name);
            assert(plan.Methods.Single(m=>m.Method==id).Status=="qualified_intra_method","Open/transitively incomplete chain is reduced within its own method: "+name);
            assert(plan.Witnesses[id].Length==2,"Both local branches remain distinguishable: "+name);
        }
        foreach(string name in new[]{".Callback(","WorkerA.Work(","WorkerB.Work("})
            assert(plan.Methods.Single(m=>m.Method==Method(name)).Status=="qualified_normal_flow","Independently entered leaf remains a normal qualified flow: "+name);
        assert(plan.Methods.Single(m=>m.Method==Method(".Exceptional(")).Status=="unresolved_analysis","Local fallback never hides incomplete finally semantics");
        assert(result.Application!.Observations.Values.All(o=>o.Kind is not ("call_attempt" or "call_statement_completed")),"No event, dispatch or call-boundary probes are generated");
        assert(plan.Witnesses[branch].Select(w=>new TraceWord(w.Where(id=>!result.Disabled.Contains(id)))).Distinct().Count()==2,"Milestone 4: reduced signatures distinguish both alternatives");
        assert(plan.Decisions.Values.Any(d=>d.Reason=="suppressed_proven_redundant"),"Redundancy is proved against ordered languages");
        assert(plan.Decisions.Values.Any(d=>d.Reason=="suppressed_by_repeat_policy"),"Repetition loss is distinguished from proved redundancy");
        var second=TraceSelectionEngine.Select(path,options);
        assert(result.Disabled.SetEquals(second.Disabled)&&result.CorpusFingerprint==second.CorpusFingerprint,"Static selection is deterministic");
        string policyFile=Path.Combine(directory,"policy.json");
        File.WriteAllText(policyFile,"""{"version":1,"name":"technical-test","rules":[{"type":"StaticFixture","member":"TechnicalCaller","role":"technical"}]}""");
        var policyResult=TraceSelectionEngine.Select(path,options with {ObservationPolicy=policyFile});
        assert(policyResult.Static!.Methods.Single(m=>m.Method==Method(".TechnicalCaller(")).Emissions!="silent","Suppressing a technical caller does not hide instrumented callee observations");
        assert(policyResult.Static!.Methods.Single(m=>m.Method==Method(".Outside(")).Status=="qualified_intra_method","Caller of a silent technical method falls back to its own-method projection");
        var detail=TraceSelectionEngine.Select(path,options with {RepeatPolicy="detail"});
        assert(detail.Static!.Decisions.Values.All(d=>d.Reason!="suppressed_by_repeat_policy"),"Detail policy retains repeated candidates");
        assert(detail.Static.Methods.Any(m=>m.Status=="unresolved_analysis"),"Recursive detail is not mislabeled as fully qualified");
        var limited=TraceSelectionEngine.Select(path,options with {MaxFlowStates=1});
        assert(limited.Status!="fallback"&&limited.Static!.Methods.Any(m=>m.Status=="unresolved_analysis"),"State budget never publishes an all-probe fallback");
        bool cancelled=false;try{TraceSelectionEngine.Select(path,options,new CancellationToken(true));}catch(OperationCanceledException){cancelled=true;}
        assert(cancelled,"Cancellation aborts static selection");
        string profile=TraceSelectionStore.Apply(path,options,result);TraceSelectionStore.VerifyIntegrity(path);
        var engine=new Engine();var task=new AITracer.MsBuildTask.InjectTracesTask {BuildEngine=engine,DatabasePath=path,Compile=new ITaskItem[]{new TaskItem(file)},IntermediateOutputPath=Path.Combine(directory,"obj")};
        assert(task.Execute(),"Milestone 5: static injector succeeds: "+string.Join(";",engine.Errors));
        string generated=File.ReadAllText(task.ModifiedCompile.Single().ItemSpec);
        var originalTree=CSharpSyntaxTree.ParseText(code);var generatedTree=CSharpSyntaxTree.ParseText(generated);
        var stripped=generatedTree.GetRoot().ReplaceNodes(generatedTree.GetRoot().DescendantNodes().OfType<ExpressionStatementSyntax>().Where(IsLog),(_,_)=>SyntaxFactory.EmptyStatement());
        // Only calls and lexical blocks may be added; no extra decisions or exception handlers.
        foreach(var kind in new[]{SyntaxKind.IfStatement,SyntaxKind.ForStatement,SyntaxKind.WhileStatement,SyntaxKind.CatchClause,SyntaxKind.FinallyClause,SyntaxKind.VariableDeclarator})
            assert(originalTree.GetRoot().DescendantNodes().Count(n=>n.IsKind(kind))==generatedTree.GetRoot().DescendantNodes().Count(n=>n.IsKind(kind)),"No runtime logic introduced: "+kind);
        foreach(var invocation in generatedTree.GetRoot().DescendantNodes().OfType<InvocationExpressionSyntax>().Where(i=>i.Expression.ToString()=="AITracer.Runtime.TraceContext.Log"))
            assert(invocation.ArgumentList.Arguments.Single().Expression is LiteralExpressionSyntax,"Every injected marker has a literal ID");
        var original=Compile(code,"OriginalStatic");var instrumented=Compile(generated,"InstrumentedStatic");
        var t=instrumented.GetType("StaticFixture")!;object instance=Activator.CreateInstance(t)!;
        IList events=(IList)instrumented.GetType("AITracer.Runtime.TraceContext")!.GetField("Events")!.GetValue(null)!;
        int Count(string method,int n){events.Clear();t.GetMethod(method)!.Invoke(instance,new object[]{n});return events.Count;}
        assert(Count("Loop",1)==Count("Loop",10000),"Loop event count is independent of iterations, including helper calls");
        assert(Count("Root",1)==Count("Root",100),"Recursion event count is independent of direct and mutual depth");
        events.Clear();t.GetMethod("Twice")!.Invoke(instance,null);
        var twiceWord=new TraceWord(events.Cast<int>().Select(id=>(long)id));
        assert(plan.Witnesses[Method(".Twice(")].Any(w=>new TraceWord(w.Where(id=>!result.Disabled.Contains(id))).Equals(twiceWord)),"Repeated calls match the exact composed continuation language");
        foreach(bool x in new[]{false,true}){
            events.Clear();int value=(int)t.GetMethod("Branch")!.Invoke(instance,new object[]{x})!;
            assert(value==(x?1:2),"Branch behavior preserved");
            File.WriteAllLines(Path.Combine(directory,"branch-"+x+".log"),events.Cast<int>().Select(id=>$"2026-11-11T10:00:00Z||test||1||{id}"));
        }
        var originalType=original.GetType("StaticFixture")!;object originalInstance=Activator.CreateInstance(originalType)!;
        originalType.GetMethod("Loop")!.Invoke(originalInstance,new object[]{10});
        object other=Activator.CreateInstance(t)!;t.GetMethod("Loop")!.Invoke(other,new object[]{10});
        assert(Equals(originalType.GetField("State")!.GetValue(originalInstance),t.GetField("State")!.GetValue(other)),"Instrumentation preserves loop effects");
        File.Copy(task.ProfileManifest,Path.Combine(directory,"fixture.aitracer.json"),true);
        TraceSelectionStore.WriteApplicationReport(directory,result);
        using(var db=new SqliteConnection($"Data Source={path};Pooling=False")){
            db.Open();using var c=db.CreateCommand();c.CommandText="SELECT count(*) FROM basic_blocks b JOIN static_flow_decisions d ON d.probe_id=b.id WHERE b.to_trace<>d.enabled";
            assert(Convert.ToInt32(c.ExecuteScalar())==0,"Static evidence and flags agree atomically");
            c.CommandText="UPDATE application_edits SET text='if(true) AITracer.Runtime.TraceContext.Log(1);' WHERE id=(SELECT e.id FROM application_edits e JOIN basic_blocks b ON b.id=e.gate_id WHERE b.to_trace=1 LIMIT 1)";c.ExecuteNonQuery();
        }
        var bad=new AITracer.MsBuildTask.InjectTracesTask {BuildEngine=new Engine(),DatabasePath=path,Compile=new ITaskItem[]{new TaskItem(file)},IntermediateOutputPath=Path.Combine(directory,"bad")};
        assert(!bad.Execute(),"Injector rejects tampered profiles that add runtime logic");
        // Restore the verified plan for offline decoder fixtures.
        TraceSelectionStore.Apply(path,options,TraceSelectionEngine.Select(path,options));
        Console.WriteLine("STATIC FLOW MILESTONES PASSED: "+directory);

        bool IsLog(ExpressionStatementSyntax s)=>s.Expression is InvocationExpressionSyntax i&&i.Expression.ToString()=="AITracer.Runtime.TraceContext.Log";
        Assembly Compile(string text,string name){
            var runtime=CSharpSyntaxTree.ParseText("namespace AITracer.Runtime { public static class TraceContext { public static System.Collections.Generic.List<int> Events=new(); public static void Log(int id) { Events.Add(id); } } }");
            var c=CSharpCompilation.Create(name,new[]{CSharpSyntaxTree.ParseText(text),runtime},references,new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
            using var stream=new MemoryStream();var emit=c.Emit(stream);assert(emit.Success,"Static source compiles: "+string.Join(";",emit.Diagnostics.Where(d=>d.Severity==DiagnosticSeverity.Error)));stream.Position=0;return AssemblyLoadContext.Default.LoadFromStream(stream);
        }
    }
    private sealed class Engine:IBuildEngine {
        public List<string> Errors=new();public bool ContinueOnError=>false;public int LineNumberOfTaskNode=>0;public int ColumnNumberOfTaskNode=>0;public string ProjectFileOfTaskNode=>"";
        public void LogErrorEvent(BuildErrorEventArgs e)=>Errors.Add(e.Message??"");public void LogWarningEvent(BuildWarningEventArgs e){}public void LogMessageEvent(BuildMessageEventArgs e){}public void LogCustomEvent(CustomBuildEventArgs e){}
        public bool BuildProjectFile(string f,string[] t,IDictionary g,IDictionary o)=>false;
    }
}
