using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Data.Sqlite;

internal static class ProbeSelectionInjectionExperiment
{
    public static int Run(string reportPath, string output)
    {
        using var report=JsonDocument.Parse(File.ReadAllText(reportPath));
        string source=report.RootElement.GetProperty("source").GetString()!;
        string database=report.RootElement.GetProperty("database").GetString()!;
        string sourceHash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(source)));
        if(sourceHash!=report.RootElement.GetProperty("source_sha256").GetString())
            throw new Exception("Source changed since selection experiment");
        int[] all=report.RootElement.GetProperty("probe_details").EnumerateArray().Select(p=>p.GetProperty("id").GetInt32()).ToArray();
        int[] selected=report.RootElement.GetProperty("selected_ids").EnumerateArray().Select(p=>p.GetInt32()).ToArray();
        var parseOptions=new CSharpParseOptions(LanguageVersion.Preview);
        var original=CSharpSyntaxTree.ParseText(File.ReadAllText(source),parseOptions);
        if(original.GetDiagnostics().Any(d=>d.Severity==DiagnosticSeverity.Error))
            throw new Exception("Original source has syntax errors");
        var results=new List<object>();
        foreach(var (name,ids) in new[]{("baseline",all),("reduced",selected)})
        {
            string dir=Path.Combine(output,name);Directory.CreateDirectory(dir);
            string copy=Path.Combine(dir,Path.GetFileName(source));File.Copy(source,copy,true);
            string dbPath=Path.Combine(dir,"injection.sqlite");
            if(File.Exists(dbPath))File.Delete(dbPath);
            using(var db=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=dbPath,Pooling=false}.ToString()))
            {
                db.Open();
                using var published=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=database,Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString());
                published.Open();using var read=published.CreateCommand();
                read.CommandText="SELECT sql FROM sqlite_master WHERE type='table' AND name='basic_blocks'";
                using var tx=db.BeginTransaction();using var cmd=db.CreateCommand();cmd.Transaction=tx;
                cmd.CommandText=(string)read.ExecuteScalar()!;cmd.ExecuteNonQuery();
                read.CommandText="SELECT * FROM basic_blocks WHERE id IN ("+string.Join(',',ids)+")";
                using var rows=read.ExecuteReader();
                cmd.CommandText="INSERT INTO basic_blocks VALUES("+string.Join(',',Enumerable.Range(0,rows.FieldCount).Select(i=>"@p"+i))+")";
                for(int i=0;i<rows.FieldCount;i++)cmd.Parameters.Add(new SqliteParameter("@p"+i,DBNull.Value));
                while(rows.Read()) {
                    for(int i=0;i<rows.FieldCount;i++)cmd.Parameters[i].Value=rows.GetName(i)=="file_path"?copy:rows.GetName(i)=="to_trace"?1:rows.GetValue(i);
                    cmd.ExecuteNonQuery();
                }
                tx.Commit();
            }
            var engine=new Engine();
            var task=new AITracer.MsBuildTask.InjectTracesTask {BuildEngine=engine,Compile=new ITaskItem[]{new TaskItem(copy)},
                DatabasePath=dbPath,IntermediateOutputPath=Path.Combine(dir,"obj")};
            if(!task.Execute() || engine.Errors.Count>0)throw new Exception(string.Join('\n',engine.Errors));
            string generatedPath=task.ModifiedCompile.Single().ItemSpec;
            var generated=CSharpSyntaxTree.ParseText(File.ReadAllText(generatedPath),parseOptions);
            var errors=generated.GetDiagnostics().Where(d=>d.Severity==DiagnosticSeverity.Error).ToArray();
            if(errors.Length>0)throw new Exception(string.Join('\n',errors.Select(d=>d.ToString())));
            var method=generated.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>()
                .Single(m=>m.Identifier.Text=="ProcessFunctionKey" && m.ParameterList.Parameters.Count==2);
            var traceStatements=method.DescendantNodes().OfType<ExpressionStatementSyntax>()
                .Where(s=>s.Expression is InvocationExpressionSyntax call && call.Expression.ToString()=="AITracer.Runtime.TraceContext.Log").ToArray();
            int[] actual=traceStatements.Select(s=>int.Parse(((InvocationExpressionSyntax)s.Expression).ArgumentList.Arguments.Single().ToString())).ToArray();
            if(!actual.OrderBy(x=>x).SequenceEqual(ids.OrderBy(x=>x)))throw new Exception("Injected IDs differ from selected set");
            var restored=generated.GetRoot().RemoveNodes(traceStatements,SyntaxRemoveOptions.KeepNoTrivia)!;
            // No wrapping is required for this target. Removing trace statements
            // must reproduce all original tokens, including every other method.
            bool tokensPreserved=restored.DescendantTokens().Select(t=>(t.RawKind,t.Text))
                .SequenceEqual(original.GetRoot().DescendantTokens().Select(t=>(t.RawKind,t.Text)));
            if(!tokensPreserved)throw new Exception("Injection changed original code tokens");
            results.Add(new {profile=name,injected_calls=actual.Length,syntax_errors=errors.Length,
                original_tokens_preserved=tokensPreserved,generated_source=generatedPath});
        }
        if(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(source)))!=sourceHash)throw new Exception("Target source changed");
        string result=JsonSerializer.Serialize(new {kind="actual_injector_syntax_and_token_test",target_source_unchanged=true,
            application_executed=false,target_semantic_compilation_performed=false,results},new JsonSerializerOptions {WriteIndented=true});
        File.WriteAllText(Path.Combine(output,"injection-result.json"),result);Console.WriteLine(result);
        return 0;
    }

    private sealed class Engine:IBuildEngine
    {
        public List<string> Errors {get;}=new();
        public bool ContinueOnError=>false;
        public int LineNumberOfTaskNode=>0;
        public int ColumnNumberOfTaskNode=>0;
        public string ProjectFileOfTaskNode=>"probe-selection-experiment";
        public void LogErrorEvent(BuildErrorEventArgs e)=>Errors.Add(e.Message??"error");
        public void LogWarningEvent(BuildWarningEventArgs e){}
        public void LogMessageEvent(BuildMessageEventArgs e){}
        public void LogCustomEvent(CustomBuildEventArgs e){}
        public bool BuildProjectFile(string projectFileName,string[] targetNames,System.Collections.IDictionary globalProperties,System.Collections.IDictionary targetOutputs)=>throw new NotSupportedException();
    }
}
