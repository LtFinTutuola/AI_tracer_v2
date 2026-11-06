using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;
using Microsoft.Data.Sqlite;
using RoslynAnalyzer;

internal static class TraceSelectionTests
{
    public static async Task Run(string directory,MetadataReference[] references,Action<bool,string> assert)
    {
        TraceObservation Row(long[] word,long train,long cal=0)=>new(new TraceWord(word),train,cal);
        var rare=new[]{Row(new long[]{1,2},980),Row(new long[]{5,3},10),Row(new long[]{5,4},10)};
        var reduced=TraceSequenceSelector.Select(rare,new HashSet<long>{1,5},.02,8);
        assert(reduced.Disabled.SetEquals(new long[]{2,3,4})&&reduced.TrainingAmbiguous==20,"Loss-budgeted incremental partition parity");
        var ordered=TraceSequenceSelector.Select(new[]{Row(new long[]{1,2},10),Row(new long[]{2,1},10)},new HashSet<long>(),0,8);
        assert(ordered.Disabled.Count==0,"AB and BA require ordered evidence");
        var cross=TraceSequenceSelector.Select(new[]{Row(new long[]{1,2},100),Row(new long[]{1,3},0,100)},new HashSet<long>{1},0,8);
        assert(cross.Disabled.Count==1&&cross.TrainingAmbiguous==0&&cross.CalibrationAmbiguous==0,"Cross-split classes compared together");
        var linear=TraceSequenceSelector.Select(new[]{Row(new long[]{1,2},100)},new HashSet<long>(),1,8);
        assert(linear.Disabled.Count==1,"A nonempty trace never becomes silent");
        var cap=TraceSequenceSelector.Select(Enumerable.Range(2,7).Select(id=>Row(new long[]{1,id},1)),new HashSet<long>{1},1,3);
        assert(cap.MaximumCandidates==3,"Candidate count capped in fit");
        var repeats=TraceSequenceSelector.Select(new[]{Row(new long[]{1,2},10),Row(new long[]{1,1,2},10)},new HashSet<long>(),0,8);
        assert(!repeats.Disabled.Contains(1),"Repeated ID carries information");
        var stopped=TraceSequenceSelector.Select(rare,new HashSet<long>(),.01,8,()=>false);
        assert(stopped.TimeLimited&&stopped.Disabled.Count==0,"Timeout retains unexamined candidates");
        var assessment=TraceSelectionEngine.Assess(new[]{new TraceWord(new long[]{1,2}),new TraceWord(new long[]{1,3})},
            new Dictionary<TraceWord,long>{{new(new long[]{1,2}),999},{new(new long[]{1,3}),1}},new HashSet<long>{2,3});
        assert(assessment.AmbiguousExecutions==1000&&assessment.EmpiricalMinorityExecutions==1,"Ambiguity and empirical minority are separate");
        assert(new TraceWord(new long[]{1,2}).Equals(new TraceWord(new long[]{1,2}))&&!new TraceWord(new long[]{1,2}).Equals(new TraceWord(new long[]{2,1})),"Structural sequence equality");
        foreach(var invalid in new[]{new TraceSelectionOptions {AmbiguityBudget=double.NaN},new() {AmbiguityBudget=-1},new() {AmbiguityBudget=1.1},new(){SamplesPerRoot=63}}) {
            bool failed=false;try{invalid.Validate();}catch(ArgumentException){failed=true;}assert(failed,"Invalid options rejected");
        }
        assert(new TraceSelectionOptions().AmbiguityBudget==.01,"One-percent default");
        foreach(double epsilon in new[]{0d,1d}) {
            var parsed=TraceSelectionOptions.ParseOption(new(),"--ambiguity-budget",epsilon.ToString(System.Globalization.CultureInfo.InvariantCulture));
            parsed.Validate();assert(parsed.Enabled&&parsed.AmbiguityBudget==epsilon,"CLI accepts both budget extremes without disabling selection");
        }
        foreach(string text in new[]{"true","1%","0,01"}) {
            bool failed=false;try{TraceSelectionOptions.ParseOption(new(),"--ambiguity-budget",text).Validate();}catch(FormatException){failed=true;}
            assert(failed,"CLI numeric types use invariant strict parsing");
        }
        assert(assessment.Counterexamples.Count==1&&assessment.Counterexamples[0].Reduced.SequenceEqual(new long[]{1}),"Qualification emits bounded ordered counterexamples");
        assert(assessment.AmbiguityFraction>.01&&TraceSelectionEngine.ValidationRejection(assessment,true)==null,"Independent ambiguity above budget warns without rejecting");
        var silent=TraceSelectionEngine.Assess(new[]{new TraceWord(new long[]{1,2})},
            new Dictionary<TraceWord,long>{{new(new long[]{1}),1}},new HashSet<long>{1});
        assert(silent.SilentExecutions==1&&TraceSelectionEngine.ValidationRejection(silent,true)=="silent_validation_trace"&&
            silent.SilentCounterexamples.Single().Events.SequenceEqual(new long[]{1}),"Unrepaired silent words still reject the profile");
        var repairCorpus=new Dictionary<TraceWord,long> {
            {new(new long[]{724,744}),3},{new(new long[]{3259}),4},{new(new long[]{3368}),4},
            {new(new long[]{744,99,744}),1},{new(Array.Empty<long>()),5},{new(new long[]{800,801}),1}
        };
        var repairDisabled=new HashSet<long>{724,744,3259,3368,99,800};
        var restored=TraceSelectionEngine.RepairActivity(repairCorpus,new[]{Row(new long[]{724,744,3259,3368},1),Row(new long[]{99},10)},repairDisabled);
        assert(restored.SetEquals(new long[]{744,3259,3368})&&repairDisabled.SetEquals(new long[]{724,99,800}),"Targeted weighted repair covers all silent words and retains unrelated removals");
        assert(TraceSelectionEngine.Assess(repairCorpus.Keys,repairCorpus,repairDisabled).SilentExecutions==0,"Repaired corpus has no new silent execution");
        var reverseDisabled=new HashSet<long>{724,744,3259,3368,99,800};
        assert(TraceSelectionEngine.RepairActivity(repairCorpus.Reverse().ToDictionary(row=>row.Key,row=>row.Value),
            new[]{Row(new long[]{724,744,3259,3368},1),Row(new long[]{99},10)},reverseDisabled).SetEquals(restored),"Repair independent of corpus enumeration order");
        var cancelledRepair=new HashSet<long>{1,2};bool repairCancelled=false;
        try{TraceSelectionEngine.RepairActivity(new Dictionary<TraceWord,long>{{new(new long[]{1,2}),1}},Array.Empty<TraceObservation>(),cancelledRepair,()=>throw new OperationCanceledException());}
        catch(OperationCanceledException){repairCancelled=true;}
        assert(repairCancelled&&cancelledRepair.SetEquals(new long[]{1,2}),"Interrupted repair does not mutate the candidate");

        const string source="class SelectionFixture { public void M(bool x) { if(x) { System.Console.WriteLine(1); } else { System.Console.WriteLine(2); } System.Console.WriteLine(3); } public void Root(){ M(true); M(false); } }";
        string sourcePath=Path.Combine(directory,"SelectionFixture.cs");File.WriteAllText(sourcePath,source);
        using var workspace=new AdhocWorkspace();
        var doc=workspace.AddProject("SelectionFixture",LanguageNames.CSharp).WithCompilationOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary))
            .AddMetadataReferences(references).AddDocument("SelectionFixture.cs",SourceText.From(source),filePath:sourcePath);
        string database=Path.Combine(directory,"selection.sqlite");
        using(var catalog=new ContextCatalog(database,"net8.0","Debug")) {
            await catalog.AnalyzeDocument(doc,catalog.AddProject(doc.Project));catalog.Complete(finalize:false);
        }
        var options=new TraceSelectionOptions {SamplesPerRoot=64,MaxDurationSeconds=30};
        var result=TraceSelectionEngine.Select(database,options);
        assert(result.Status!="fallback"&&result.Disabled.Count>0,"Real CFG selection removes redundant completion probes");
        assert(result.Roots.Count==2&&result.Roots.All(root=>root.Status=="qualified"),"Methods without own probes participate through calls");
        assert(result.Validation?.SilentExecutions==0,"Independent sample activity retained");
        var second=TraceSelectionEngine.Select(database,options);
        assert(result.Disabled.SetEquals(second.Disabled)&&result.CorpusFingerprint==second.CorpusFingerprint,"Deterministic selection on the same catalog");
        long rootMethod;
        using(var db=new SqliteConnection($"Data Source={database};Pooling=False")) {
            db.Open();using var cmd=db.CreateCommand();cmd.CommandText="SELECT id FROM methods WHERE signature LIKE '%Root()'";rootMethod=Convert.ToInt64(cmd.ExecuteScalar());
        }
        var resources=new SelectionResources(options,CancellationToken.None);
        using(var graph=new TraceSelectionModel(database,resources,options.MaxMemoryMb)) {
            graph.Load();var full=graph.Sample(rootMethod,0,0,options with {MaxCallDepth=1});
            var opaque=graph.Sample(rootMethod,0,0,options with {MaxCallDepth=0});
            assert(full.Word?.Events.Length==4&&opaque.Word?.Events.Length==0,"Repeated calls return to their actual continuation");
            graph.ProtectUnqualifiedMethods(new[]{rootMethod});
            assert(!result.Disabled.Any(graph.Protected.ContainsKey),"Unqualified caller does not freeze separately qualified callee IDs");
            graph.ProtectUnqualifiedMethods(graph.Methods.Values.Where(method=>method.Probes.Count>0).Select(method=>method.Id));
            assert(result.Disabled.All(graph.Protected.ContainsKey),"Unqualified owners still protect their own probe IDs");
        }
        var limited=TraceSelectionEngine.Select(database,options with {MaxMemoryMb=1});
        assert(limited.Status=="fallback"&&limited.FallbackReason=="memory_limit"&&limited.Disabled.Count==0,"Memory fallback enables the baseline");
        var timed=TraceSelectionEngine.Select(database,options with {MaxDurationSeconds=.000001});
        assert(timed.Status=="fallback"&&timed.Disabled.Count==0,"Deadline fallback enables the baseline");
        bool cancelled=false;try{TraceSelectionEngine.Select(database,options,new CancellationToken(true));}catch(OperationCanceledException){cancelled=true;}
        assert(cancelled,"Cancellation is not swallowed as fallback");
        using(var db=new SqliteConnection($"Data Source={database};Pooling=False")) {
            db.Open();using var cmd=db.CreateCommand();cmd.CommandText="CREATE TRIGGER selection_failure BEFORE INSERT ON trace_selection_decisions BEGIN SELECT RAISE(ABORT,'test rollback'); END";cmd.ExecuteNonQuery();
        }
        bool rolledBack=false;try{TraceSelectionStore.Apply(database,options,result);}catch(SqliteException){rolledBack=true;}
        using(var db=new SqliteConnection($"Data Source={database};Pooling=False")) {
            db.Open();using var cmd=db.CreateCommand();cmd.CommandText="SELECT (SELECT count(*) FROM trace_selection_profiles)+(SELECT count(*) FROM basic_blocks WHERE to_trace=0)";
            assert(rolledBack&&Convert.ToInt64(cmd.ExecuteScalar())==0,"Atomic decisions and flags roll back together");
            cmd.CommandText="DROP TRIGGER selection_failure";cmd.ExecuteNonQuery();
        }
        string profile=TraceSelectionStore.Apply(database,options,result);TraceSelectionStore.VerifyIntegrity(database);
        using(var db=new SqliteConnection($"Data Source={database};Pooling=False")) {
            db.Open();using var cmd=db.CreateCommand();cmd.CommandText="SELECT count(*) FROM basic_blocks WHERE to_trace=0";
            assert(Convert.ToInt64(cmd.ExecuteScalar())==result.Disabled.Count,"Flag application uses existing IDs");
            cmd.CommandText="SELECT value FROM analysis_manifest WHERE key='schema_version'";assert((string?)cmd.ExecuteScalar()=="4","Schema 4 published contract");
            cmd.CommandText="SELECT count(*) FROM trace_selection_decisions WHERE profile_id=@id";cmd.Parameters.AddWithValue("@id",profile);
            assert(Convert.ToInt64(cmd.ExecuteScalar())==result.ProbeCount,"Every legacy probe has an auditable decision");
        }
        bool storeCancelled=false;try{TraceSelectionStore.Apply(database,options,result,new CancellationToken(true));}catch(OperationCanceledException){storeCancelled=true;}
        using(var db=new SqliteConnection($"Data Source={database};Pooling=False")) {
            db.Open();using var cmd=db.CreateCommand();cmd.CommandText="SELECT id FROM trace_selection_profiles";
            assert(storeCancelled&&(string?)cmd.ExecuteScalar()==profile,"Cancelled application keeps the committed profile");
        }
        var disabled=TraceSelectionEngine.Select(database,options with {Enabled=false});
        assert(disabled.Status=="disabled"&&disabled.Disabled.Count==0,"Selection can be explicitly disabled");

        const string incompleteSource="""
            class IncompleteCallerFixture {
                public void Callee(bool x) {
                    if(x) { System.Console.WriteLine(1); } else { System.Console.WriteLine(2); }
                    System.Console.WriteLine(3);
                }
                public void Caller(bool x) {
                    if(x) { System.Console.WriteLine(4); }
                    try { Callee(x); } finally { System.Console.WriteLine(5); }
                }
            }
            """;
        string incompletePath=Path.Combine(directory,"IncompleteCallerFixture.cs");File.WriteAllText(incompletePath,incompleteSource);
        var incompleteDoc=workspace.AddProject("IncompleteCallerFixture",LanguageNames.CSharp)
            .WithCompilationOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary)).AddMetadataReferences(references)
            .AddDocument("IncompleteCallerFixture.cs",SourceText.From(incompleteSource),filePath:incompletePath);
        string incompleteDb=Path.Combine(directory,"incomplete-caller-selection.sqlite");
        using(var catalog=new ContextCatalog(incompleteDb,"net8.0","Debug")) {
            await catalog.AnalyzeDocument(incompleteDoc,catalog.AddProject(incompleteDoc.Project));catalog.Complete(finalize:false);
        }
        var localResult=TraceSelectionEngine.Select(incompleteDb,options);
        using(var db=new SqliteConnection($"Data Source={incompleteDb};Pooling=False")) {
            db.Open();using var cmd=db.CreateCommand();cmd.CommandText="SELECT id,signature FROM methods";
            var names=new Dictionary<string,long>();using(var rows=cmd.ExecuteReader())while(rows.Read())names[rows.GetString(1)]=rows.GetInt64(0);
            long caller=names.Single(row=>row.Key.Contains(".Caller(")).Value,callee=names.Single(row=>row.Key.Contains(".Callee(")).Value;
            assert(localResult.Roots.Single(root=>root.MethodId==caller).Status=="unqualified_fit"&&
                localResult.Roots.Single(root=>root.MethodId==callee).Status=="qualified","Finally caller incomplete while callee independently qualifies");
            cmd.CommandText="SELECT legacy_id FROM legacy_block_links WHERE method_id=@method";cmd.Parameters.AddWithValue("@method",caller);
            var callerIds=new HashSet<long>();using(var rows=cmd.ExecuteReader())while(rows.Read())callerIds.Add(rows.GetInt64(0));
            assert(callerIds.Count>0&&callerIds.All(id=>localResult.Protected.ContainsKey(id)&&!localResult.Disabled.Contains(id)),"Incomplete caller retains its own probes");
            cmd.Parameters["@method"].Value=callee;var calleeIds=new HashSet<long>();using(var rows=cmd.ExecuteReader())while(rows.Read())calleeIds.Add(rows.GetInt64(0));
            assert(localResult.Status=="applied_partial"&&localResult.Disabled.Overlaps(calleeIds)&&localResult.Validation?.SilentExecutions==0,
                "Qualified callee reduction survives incomplete caller with explicit partial coverage");
        }
    }

    public static void SelectWords(string input,string output)
    {
        using var doc=JsonDocument.Parse(File.ReadAllText(input));var root=doc.RootElement;
        var rows=root.GetProperty("rows").EnumerateArray().Select(row=>new TraceObservation(new(row.GetProperty("word").EnumerateArray().Select(id=>id.GetInt64())),row.GetProperty("training").GetInt64(),row.GetProperty("calibration").GetInt64())).ToArray();
        var result=TraceSequenceSelector.Select(rows,root.GetProperty("protected").EnumerateArray().Select(id=>id.GetInt64()).ToHashSet(),root.GetProperty("epsilon").GetDouble(),root.GetProperty("max_candidates").GetInt32());
        File.WriteAllText(output,JsonSerializer.Serialize(new {disabled=result.Disabled.OrderBy(id=>id).ToArray(),training=result.TrainingAmbiguous,calibration=result.CalibrationAmbiguous,maximum=result.MaximumCandidates}));
    }
}
