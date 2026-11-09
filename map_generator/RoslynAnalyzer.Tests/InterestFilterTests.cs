using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;
using Microsoft.Data.Sqlite;
using RoslynAnalyzer;

internal static class InterestFilterTests
{
    public static async Task Run(string directory,MetadataReference[] references,Action<bool,string> assert)
    {
        MethodDeclarationSyntax Method(string code)=>(MethodDeclarationSyntax)SyntaxFactory.ParseMemberDeclaration(code)!;
        assert(ApplicationInterestFilter.IsCalculationOrRead(Method("int Compute(int x) { int n=x; while(n>0)n--; return n; }"),Array.Empty<string>()),"Local computation has reproducible mechanical evidence");
        assert(!ApplicationInterestFilter.IsCalculationOrRead(Method("int Compute(int x) { State=x; return x; }"),Array.Empty<string>()),"Shared writes prevent calculation classification");
        assert(!ApplicationInterestFilter.IsCalculationOrRead(Method("int Compute(int[] x) { x[0]=1; return 1; }"),Array.Empty<string>()),"Writes through an alias prevent calculation classification");
        assert(!ApplicationInterestFilter.IsCalculationOrRead(Method("int Compute(ref int x) { x++; return x; }"),Array.Empty<string>()),"Ref parameters prevent calculation classification");
        assert(!ApplicationInterestFilter.IsCalculationOrRead(Method("int Compute() { return Unknown(); }"),new[]{"Sample.Unknown()"}),"Unknown calls do not become a purity claim");
        string source="class InterestFixture { int State; bool CheckPermission() => true; void OpenDrawer() {} public void ProcessKey(int key) { switch(key) { case 1: if(CheckPermission()) { OpenDrawer(); } break; case 2: State=2; throw new System.InvalidOperationException(); } } public void ConvertMany(int x) { "+
            string.Join(" ",Enumerable.Range(1,90).Select(n=>$"if(x=={n}) {{ System.Console.WriteLine({n}); }}"))+" } }";
        string path=Path.Combine(directory,"InterestFixture.cs");File.WriteAllText(path,source);
        using var workspace=new AdhocWorkspace();
        var document=workspace.AddProject("InterestFixture",LanguageNames.CSharp)
            .WithCompilationOptions(new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary))
            .AddMetadataReferences(references).AddDocument("InterestFixture.cs",SourceText.From(source),filePath:path);
        string dbPath=Path.Combine(directory,"interest-fixture.sqlite");
        using(var catalog=new ContextCatalog(dbPath,"net8.0","Debug")) {
            await catalog.AnalyzeDocument(document,catalog.AddProject(document.Project));catalog.Complete(finalize:false);
        }
        var options=new TraceSelectionOptions {InterestFilterEnabled=true,SamplesPerRoot=64,MaxDurationSeconds=60};
        InterestFilterResult Select(double fraction) {
            var limits=options with {InterestTargetFraction=fraction};var resources=new SelectionResources(limits,CancellationToken.None){PhaseFraction=1};
            return ApplicationInterestFilter.Select(dbPath,limits,new HashSet<long>(),resources.Check,resources.Reserve,resources.Release);
        }
        var first=Select(.325);var second=Select(.325);
        assert(first.Enabled.SetEquals(second.Enabled)&&first.Reasons.OrderBy(row=>row.Key).SequenceEqual(second.Reasons.OrderBy(row=>row.Key)),"Interest decisions deterministic for identical inputs");
        assert(first.UncoveredRequirements==0&&first.Enabled.IsSupersetOf(first.RequiredIds),"All structural observation units have a retained witness");
        assert(first.Enabled.Count<first.BaselineCount&&first.Reasons.Values.Any(reason=>reason=="interest_technical_detail_suppressed"),"Technical branch detail can be suppressed");
        assert(first.Evidence.Any(item=>item.Rule=="application_decision")&&first.Evidence.Any(item=>item.Rule=="dispatch_case")&&first.Evidence.Any(item=>item.Rule=="external_or_domain_operation"),"Permission, dispatch and effect-call regions classified");
        assert(first.SourceFilesVerified==1&&first.SourceFilesUnavailable==0,"Physical source fingerprint verified");
        var tight=Select(.01);
        assert(tight.Enabled.Count>tight.TargetCount&&tight.UncoveredRequirements==0,"Count target cannot delete required witnesses");
        var selection=TraceSelectionEngine.Select(dbPath,options);
        assert(selection.Status=="applied_partial"&&selection.Interest!=null&&selection.FirstLevel!=null,"Second pass runs after the first profile and declares experimental coverage");
        assert(selection.Interest!.AuditSilentAfterRepair==0&&selection.Protected.Keys.All(id=>!selection.Disabled.Contains(id)),"Audit and integrity guards survive profile application");
        TraceSelectionStore.Apply(dbPath,options,selection);TraceSelectionStore.VerifyIntegrity(dbPath);
        using(var db=new SqliteConnection($"Data Source={dbPath};Pooling=False")) {
            db.Open();using var cmd=db.CreateCommand();cmd.CommandText="SELECT count(*) FROM trace_interest_evidence";
            assert(Convert.ToInt64(cmd.ExecuteScalar())>0,"Interest evidence persists alongside the numeric trace contract");
            cmd.CommandText="SELECT count(*) FROM basic_blocks WHERE to_trace=0";
            assert(Convert.ToInt64(cmd.ExecuteScalar())==selection.Disabled.Count,"Final flags match the filtered decisions");
        }
        File.WriteAllText(path,source+" // changed");
        bool mismatch=false;try{Select(.325);}catch(InvalidOperationException){mismatch=true;}
        assert(mismatch,"Changed source cannot silently reuse the old CFG catalog");File.WriteAllText(path,source);
        bool cancelled=false;try{ApplicationInterestFilter.Select(dbPath,options,new HashSet<long>(),()=>throw new OperationCanceledException(),_=>{},_=>{});}catch(OperationCanceledException){cancelled=true;}
        assert(cancelled,"Interest filter cancellation propagates");
    }
}
