using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.Data.Sqlite;
using RoslynAnalyzer;

internal static class InjectionTests
{
    public static void Run(string directory,MetadataReference[] references,Action<bool,string> assert)
    {
        const string source="class Injection { public int M(int x) { if(x==1) return 1; return 2; } }";
        string path=Path.Combine(directory,"Injection.cs");File.WriteAllText(path,source);
        var tree=CSharpSyntaxTree.ParseText(source,path:path);
        var compilation=CSharpCompilation.Create("Injection",new[]{tree},references,new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var blocks=new BlockExtractor().ExtractBlocks(compilation.GetSemanticModel(tree),tree.GetRoot());
        assert(blocks.Any(b=>b.WrapInBlock),"Unbraced branch wrapper selected");
        foreach(bool old in new[]{false,true}) {
            string dbPath=Path.Combine(directory,"inject-"+old+".sqlite");if(File.Exists(dbPath))File.Delete(dbPath);
            new SqliteRepository(dbPath).InitializeDatabase();
            var selected=old?blocks.Where(b=>!b.WrapInBlock).ToArray():blocks.ToArray();
            new SqliteRepository(dbPath).SaveBlocksBatch(selected.Select(b=>new BasicBlockRecord {
                ProjectName="Injection",FilePath=path,MethodSignature=b.MethodSignature,ScopeStartLine=b.ScopeStartLine,ScopeEndLine=b.ScopeEndLine,
                BlockStartLine=b.BlockStartLine,BlockEndLine=b.BlockEndLine,InjectionLine=b.StartLine,InjectionOffset=b.InjectionOffset,
                Reason=b.Reason,WrapInBlock=b.WrapInBlock,StatementEndOffset=b.StatementEndOffset }));
            if(old) {
                using var db=new SqliteConnection($"Data Source={dbPath};Pooling=False");db.Open();using var cmd=db.CreateCommand();
                cmd.CommandText="ALTER TABLE basic_blocks DROP COLUMN wrap_in_block; ALTER TABLE basic_blocks DROP COLUMN statement_end_offset";cmd.ExecuteNonQuery();
            }
            var engine=new Engine();var task=new AITracer.MsBuildTask.InjectTracesTask {BuildEngine=engine,Compile=new ITaskItem[]{new TaskItem(path)},DatabasePath=dbPath,IntermediateOutputPath=Path.Combine(directory,"obj-"+old)};
            assert(task.Execute() && engine.Errors==0,"Task executes with "+(old?"old":"new")+" schema");
            string generated=File.ReadAllText(task.ModifiedCompile.Single().ItemSpec);
            var generatedTree=CSharpSyntaxTree.ParseText(generated);
            var runtime=CSharpSyntaxTree.ParseText("namespace AITracer.Runtime { public static class TraceContext { public static void Log(int id) {} } }");
            var result=CSharpCompilation.Create("Injected",new[]{generatedTree,runtime},references,new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
            assert(!result.GetDiagnostics().Any(d=>d.Severity==DiagnosticSeverity.Error),"Injected source compiles");
            assert(generated.Split("TraceContext.Log(").Length-1==selected.Length,"Exactly one call per injection offset");
        }
        var sharedPath=Path.Combine(directory,"InjectionShared.cs");
        const string sharedSource="class InjectionShared { int M(int x) { if (x==0) return 0; if (x==1) return 1; if (x==2) return 2; return 3; } }";
        File.WriteAllText(sharedPath,sharedSource);
        var variants=new[]{Array.Empty<string>(),new[]{"SECOND"}};
        var selections=variants.Select(symbols=>{
            var syntax=CSharpSyntaxTree.ParseText(sharedSource,new CSharpParseOptions(preprocessorSymbols:symbols),sharedPath);
            var variantCompilation=CSharpCompilation.Create("SharedVariant",new[]{syntax},references,new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
            return new BlockExtractor().ExtractBlocks(variantCompilation.GetSemanticModel(syntax),syntax.GetRoot()).ToArray();
        }).ToArray();
        selections[0]=selections[0].Take(selections[0].Length-2).ToArray();
        var union=selections.SelectMany(points=>points).GroupBy(point=>point.InjectionOffset).Select(group=>group.First()).ToArray();
        assert(union.Length>selections[0].Length,"Shared file has variant-exclusive probes");
        var unionDb=Path.Combine(directory,"inject-union.sqlite");
        new SqliteRepository(unionDb).InitializeDatabase();
        new SqliteRepository(unionDb).SaveBlocksBatch(union.Select(point=>new BasicBlockRecord {
            ProjectName="First",FilePath=sharedPath,MethodSignature=point.MethodSignature,
            ScopeStartLine=point.ScopeStartLine,ScopeEndLine=point.ScopeEndLine,
            BlockStartLine=point.BlockStartLine,BlockEndLine=point.BlockEndLine,
            InjectionLine=point.StartLine,InjectionOffset=point.InjectionOffset,Reason=point.Reason,
            ToTrace=true,WrapInBlock=point.WrapInBlock,StatementEndOffset=point.StatementEndOffset
        }));
        foreach(var symbols in variants) {
            var engine=new Engine();
            var task=new AITracer.MsBuildTask.InjectTracesTask {BuildEngine=engine,Compile=new ITaskItem[]{new TaskItem(sharedPath)},DatabasePath=unionDb,
                IntermediateOutputPath=Path.Combine(directory,"obj-union-"+symbols.Length)};
            assert(task.Execute() && engine.Errors==0,"Union injection succeeds for both project variants");
            var generated=File.ReadAllText(task.ModifiedCompile.Single().ItemSpec);
            assert(generated.Split("TraceContext.Log(").Length-1==union.Length,"One trace call per union offset in both variants");
            var generatedTree=CSharpSyntaxTree.ParseText(generated,new CSharpParseOptions(preprocessorSymbols:symbols));
            var runtime=CSharpSyntaxTree.ParseText("namespace AITracer.Runtime { public static class TraceContext { public static void Log(int id) {} } }");
            var compilationWithTraces=CSharpCompilation.Create("InjectedShared",new[]{generatedTree,runtime},references,new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
            assert(!compilationWithTraces.GetDiagnostics().Any(d=>d.Severity==DiagnosticSeverity.Error),"Union-injected source compiles for variant "+symbols.Length);
        }
        // Selection changes only flags; the same injector reads old and new catalogs.
        using(var db=new SqliteConnection($"Data Source={unionDb};Pooling=False")) {
            db.Open();using var cmd=db.CreateCommand();
            cmd.CommandText="UPDATE basic_blocks SET to_trace=0 WHERE id=(SELECT max(id) FROM basic_blocks)";cmd.ExecuteNonQuery();
        }
        foreach(var symbols in variants) {
            var engine=new Engine();
            var task=new AITracer.MsBuildTask.InjectTracesTask {BuildEngine=engine,Compile=new ITaskItem[]{new TaskItem(sharedPath)},DatabasePath=unionDb,
                IntermediateOutputPath=Path.Combine(directory,"obj-selected-"+symbols.Length)};
            assert(task.Execute()&&engine.Errors==0,"Selected union injection succeeds");
            var syntax=CSharpSyntaxTree.ParseText(File.ReadAllText(task.ModifiedCompile.Single().ItemSpec),new CSharpParseOptions(preprocessorSymbols:symbols));
            var calls=syntax.GetRoot().DescendantNodes().OfType<Microsoft.CodeAnalysis.CSharp.Syntax.InvocationExpressionSyntax>()
                .Where(call=>call.Expression.ToString().EndsWith("TraceContext.Log")).ToArray();
            assert(calls.Length==union.Length-1,"Disabled offset emits no call in either variant");
            assert(calls.All(call=>call.ArgumentList.Arguments.Single().ToString()!=union.Length.ToString()),"Suppressed ID absent from generated source");
            var runtime=CSharpSyntaxTree.ParseText("namespace AITracer.Runtime { public static class TraceContext { public static void Log(int id) {} } }");
            assert(!CSharpCompilation.Create("SelectedShared",new[]{syntax,runtime},references,new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary))
                .GetDiagnostics().Any(item=>item.Severity==DiagnosticSeverity.Error),"Selected wrapping remains compilable");
        }
        var target=System.Xml.Linq.XDocument.Load(Path.Combine(AppContext.BaseDirectory,"../../../../../AITracer.MsBuildTask/AITracer.targets"));
        string condition=target.Descendants().Single(e=>e.Name.LocalName=="Target" && (string?)e.Attribute("Name")=="AITracerInject").Attribute("Condition")!.Value;
        assert(condition.Contains("DesignTimeBuild") && condition.Contains("AITracerAnalysis"),"Injection disabled in analysis mode");
    }
    private sealed class Engine:IBuildEngine
    {
        public int Errors;
        public bool ContinueOnError=>false;
        public int LineNumberOfTaskNode=>0;
        public int ColumnNumberOfTaskNode=>0;
        public string ProjectFileOfTaskNode=>"test";
        public void LogErrorEvent(BuildErrorEventArgs e)=>Errors++;
        public void LogWarningEvent(BuildWarningEventArgs e){}
        public void LogMessageEvent(BuildMessageEventArgs e){}
        public void LogCustomEvent(CustomBuildEventArgs e){}
        public bool BuildProjectFile(string projectFileName,string[] targetNames,System.Collections.IDictionary globalProperties,System.Collections.IDictionary targetOutputs)=>throw new NotSupportedException();
    }
}
