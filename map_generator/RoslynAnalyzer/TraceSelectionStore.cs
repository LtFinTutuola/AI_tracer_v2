using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Diagnostics;
using Microsoft.Data.Sqlite;

namespace RoslynAnalyzer;

public static class TraceSelectionStore
{
    public static void WriteApplicationReport(string directory,TraceSelectionResult result)
    {
        if(result.Application is not { } plan)return;
        File.WriteAllText(Path.Combine(directory,"application-profile-report.json"),JsonSerializer.Serialize(new {
            summary=plan.Summary,entries=plan.Entries,observations=plan.Observations.Values.OrderBy(o=>o.Method).ThenBy(o=>o.Kind),
            memory_bytes=result.PeakBufferBytes,duration_seconds=result.DurationSeconds},new JsonSerializerOptions {WriteIndented=true}));
    }
    public const string Schema="""
      CREATE TABLE IF NOT EXISTS trace_selection_profiles(
        id TEXT PRIMARY KEY,algorithm TEXT NOT NULL,status TEXT NOT NULL,options_json TEXT NOT NULL,
        input_fingerprint TEXT NOT NULL,corpus_fingerprint TEXT NOT NULL,metrics_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS trace_selection_decisions(
        legacy_id INTEGER PRIMARY KEY REFERENCES basic_blocks(id),profile_id TEXT NOT NULL REFERENCES trace_selection_profiles(id),
        enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),reason TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS selection_decisions_profile ON trace_selection_decisions(profile_id);
      CREATE TABLE IF NOT EXISTS trace_selection_roots(
        method_id INTEGER PRIMARY KEY REFERENCES methods(id),profile_id TEXT NOT NULL REFERENCES trace_selection_profiles(id),
        status TEXT NOT NULL,attempts_json TEXT NOT NULL,accepted_json TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS trace_interest_evidence(
        legacy_id INTEGER NOT NULL REFERENCES basic_blocks(id),rule TEXT NOT NULL,detail TEXT NOT NULL,
        PRIMARY KEY(legacy_id,rule,detail));
      """;

    public static string Apply(string path,TraceSelectionOptions options,TraceSelectionResult result,CancellationToken token=default)
    {
        token.ThrowIfCancellationRequested();options.Validate();
        if(result.Status is not ("applied" or "applied_partial" or "disabled" or "fallback")||
            (result.Status is "disabled" or "fallback"&&result.Disabled.Count>0))throw new InvalidOperationException("Unvalidated selection result");
        using var db=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=path,Pooling=false}.ToString());db.Open();
        using(var setup=db.CreateCommand()){setup.CommandText="PRAGMA foreign_keys=ON";setup.ExecuteNonQuery();}
        using var tx=db.BeginTransaction();
        using var cmd=db.CreateCommand();cmd.Transaction=tx;
        void Run(string sql,params object[] values) {
            cmd.Parameters.Clear();cmd.CommandText=sql;
            for(int i=0;i<values.Length;i++)cmd.Parameters.AddWithValue("@p"+i,values[i]);cmd.ExecuteNonQuery();
        }
        string? Meta(string key) {
            cmd.Parameters.Clear();cmd.CommandText="SELECT value FROM analysis_manifest WHERE key=@key";cmd.Parameters.AddWithValue("@key",key);
            return cmd.ExecuteScalar() as string;
        }
        void Set(string key,string value)=>Run("INSERT INTO analysis_manifest(key,value) VALUES(@p0,@p1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",key,value);
        string oldState=Meta("state")??"";
        if(result.Application==null&&Meta("injection_contract")=="application_edits_v1")throw new InvalidOperationException("An application catalog cannot be requalified as legacy/disabled; regenerate with that mode");
        if(oldState!="graph_validated"&&oldState!="validated")throw new InvalidOperationException("Selection requires a validated graph");
        if(Meta("schema_version") is not ("3" or "4" or "5" or "6"))throw new InvalidOperationException("Selection requires context schema 3..6; regenerate the catalog");
        string extraction=Meta("extraction_coverage")??Meta("coverage")??"partial";
        string knownInputs=Meta("input_manifest")??"[]",previousPolicy=Meta("application_policy_path")??"";
        InputRegistry.VerifyManifest(knownInputs,token,result.Application==null?null:previousPolicy.Length==0?null:previousPolicy);
        if(result.Application!=null) {
            string updated=InputRegistry.ReplacePolicy(knownInputs,previousPolicy,options.ObservationPolicy);
            Set("input_manifest",updated);Set("fingerprint",ContextCatalog.Id(updated));Set("application_policy_path",Path.GetFullPath(options.ObservationPolicy));
        }
        string input=Meta("fingerprint")??"";
        Run(Schema);
        result.Application?.Inputs.Verify(token);
        result.Application?.Persist(db,tx,token);
        var baseline=new Dictionary<long,bool>();
        cmd.Parameters.Clear();cmd.CommandText="SELECT id,to_trace FROM basic_blocks ORDER BY id";
        using(var rows=cmd.ExecuteReader())while(rows.Read())baseline[rows.GetInt64(0)]=rows.GetInt32(1)!=0;
        if(result.Disabled.Any(id=>!baseline.ContainsKey(id)||result.Application==null&&!baseline[id]))throw new InvalidOperationException("Selection contains an unknown or baseline-disabled ID");
        if(result.Disabled.Overlaps(result.Protected.Keys))throw new InvalidOperationException("A protected probe was disabled");
        result.ProbeCount=baseline.Count;
        result.BaselineDisabledCount=result.Application==null?baseline.Count(probe=>!probe.Value):0;
        string optionsJson=JsonSerializer.Serialize(options),metrics=JsonSerializer.Serialize(result.Summary);
        string id=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(result.AlgorithmName+(result.Interest==null?"":InterestFilterResult.RulesVersion)+input+optionsJson+result.CorpusFingerprint+result.Status+
            string.Join(',',result.Disabled.OrderBy(id=>id))))).ToLowerInvariant();
        Run("DELETE FROM trace_interest_evidence; DELETE FROM trace_selection_decisions; DELETE FROM trace_selection_roots; DELETE FROM trace_selection_profiles");
        Run("INSERT INTO trace_selection_profiles VALUES(@p0,@p1,@p2,@p3,@p4,@p5,@p6)",id,result.AlgorithmName,result.Status,optionsJson,input,result.CorpusFingerprint,metrics);
        // Reuse the bulk command, preserving IDs and every other legacy field.
        using var decision=db.CreateCommand();decision.Transaction=tx;
        decision.CommandText="INSERT INTO trace_selection_decisions VALUES(@id,@profile,@enabled,@reason)";
        decision.Parameters.AddWithValue("@id",0L);decision.Parameters.AddWithValue("@profile",id);
        decision.Parameters.AddWithValue("@enabled",1);decision.Parameters.AddWithValue("@reason","");
        using var update=db.CreateCommand();update.Transaction=tx;update.CommandText="UPDATE basic_blocks SET to_trace=@enabled WHERE id=@id";update.Parameters.AddWithValue("@id",0L);update.Parameters.AddWithValue("@enabled",0);
        foreach(var (probe,enabled) in baseline) {
            token.ThrowIfCancellationRequested();bool keep=(enabled||result.Application!=null)&&!result.Disabled.Contains(probe);
            string reason=result.Application!=null?result.Application.Reasons.GetValueOrDefault(probe)??"application_internal_detail_suppressed":!enabled?"baseline_disabled":result.Protected.GetValueOrDefault(probe)??
                (result.Status=="fallback"?"baseline_fallback":result.Interest?.Reasons.GetValueOrDefault(probe)??
                (result.Disabled.Contains(probe)?"suppressed_within_fit_budget":result.RestoredForActivity.Contains(probe)?"restored_for_activity":result.Status=="disabled"?"selection_disabled":"retained"));
            decision.Parameters["@id"].Value=probe;decision.Parameters["@enabled"].Value=keep?1:0;decision.Parameters["@reason"].Value=reason;decision.ExecuteNonQuery();
            if(enabled!=keep){update.Parameters["@id"].Value=probe;update.Parameters["@enabled"].Value=keep?1:0;update.ExecuteNonQuery();}
        }
        foreach(var root in result.Roots) {
            token.ThrowIfCancellationRequested();Run("INSERT INTO trace_selection_roots VALUES(@p0,@p1,@p2,@p3,@p4)",
                root.MethodId,id,root.Status,JsonSerializer.Serialize(root.Attempts),JsonSerializer.Serialize(root.Accepted));
        }
        if(result.Interest!=null)foreach(var evidence in result.Interest.Evidence) {
            token.ThrowIfCancellationRequested();Run("INSERT OR IGNORE INTO trace_interest_evidence VALUES(@p0,@p1,@p2)",evidence.Id,evidence.Rule,evidence.Detail);
        }
        Set("schema_version",Meta("schema_version")=="6"?"6":"5");Set("extraction_coverage",extraction);
        Set("interest_filter_status",result.Interest==null?(options.InterestFilterEnabled?"not_applied":"disabled"):result.Status=="fallback"?"discarded":"experimental_applied");
        Set("selection_profile_id",id);Set("selection_status",result.Status);Set("selection_options",optionsJson);
        Set("selection_summary",metrics);Set("selection_coverage",result.Partial?"partial":"complete_for_declared_model");
        var counts=JsonSerializer.Deserialize<Dictionary<string,long>>(Meta("counts")??"{}")??new();
        counts["trace_selection_profiles"]=1;counts["trace_selection_decisions"]=baseline.Count;counts["trace_selection_roots"]=result.Roots.Count;
        counts["trace_interest_evidence"]=result.Interest?.Evidence.Distinct().LongCount()??0;
        if(result.Application!=null) {
            foreach(var table in new[]{"basic_blocks","legacy_probe_variants","application_entries","application_observations","application_locations","application_probe_bindings","application_probe_contexts","application_placements","application_edits","application_method_summaries"}) {
                cmd.CommandText="SELECT count(*) FROM "+table;cmd.Parameters.Clear();counts[table]=Convert.ToInt64(cmd.ExecuteScalar());
            }
        }
        Set("counts",JsonSerializer.Serialize(counts));
        Set("coverage",extraction=="partial"||result.Partial?"partial":"complete_for_model");
        cmd.Parameters.Clear();cmd.CommandText="SELECT count(*) FROM trace_selection_decisions d JOIN basic_blocks b ON b.id=d.legacy_id WHERE b.to_trace<>d.enabled";
        if(Convert.ToInt64(cmd.ExecuteScalar())!=0)throw new InvalidOperationException("Selection flags do not match decisions");
        cmd.CommandText="PRAGMA foreign_key_check";using(var rows=cmd.ExecuteReader())if(rows.Read())throw new InvalidOperationException("Selection foreign keys failed");
        result.Application?.Inputs.Verify(token);token.ThrowIfCancellationRequested();Set("state","validated");tx.Commit();
        return id;
    }

    public static void VerifyIntegrity(string path)
    {
        using var db=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=path,Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString());db.Open();
        using var cmd=db.CreateCommand();cmd.CommandText="PRAGMA integrity_check";
        if((string?)cmd.ExecuteScalar()!="ok")throw new InvalidOperationException("SQLite integrity check failed");
        cmd.CommandText="PRAGMA foreign_key_check";using var rows=cmd.ExecuteReader();if(rows.Read())throw new InvalidOperationException("SQLite foreign key check failed");
    }

    public static async Task<int> QualifyCopy(string[] args,Action<string,object?> progress)
    {
        var clock=Stopwatch.StartNew();
        if(args.Length<3)throw new ArgumentException("Usage: --select-catalog <input.sqlite> <output-directory> [selection options]");
        string source=Path.GetFullPath(args[1]),output=Path.GetFullPath(args[2]);
        if(string.Equals(Path.GetDirectoryName(source),output,StringComparison.OrdinalIgnoreCase))throw new ArgumentException("Qualification output must differ from the input directory");
        var options=new TraceSelectionOptions();
        for(int i=3;i<args.Length;i+=2){if(i+1>=args.Length)throw new ArgumentException("Missing selection option value");options=TraceSelectionOptions.ParseOption(options,args[i],args[i+1]);}
        options.Validate();Directory.CreateDirectory(output);
        using var cancellation=new CancellationTokenSource();ConsoleCancelEventHandler handler=(_,e)=>{e.Cancel=true;cancellation.Cancel();};Console.CancelKeyPress+=handler;
        try {
            using var staging=new CatalogStaging(output);
            using(var input=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=source,Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString()))
            using(var copy=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=staging.Path,Pooling=false}.ToString())) {
                input.Open();copy.Open();using var check=input.CreateCommand();check.CommandText="SELECT value FROM analysis_manifest WHERE key='state'";
                if((string?)check.ExecuteScalar()!="validated")throw new InvalidOperationException("Unvalidated qualification input");
                check.CommandText="SELECT value FROM analysis_manifest WHERE key='schema_version'";
                if(check.ExecuteScalar() as string is not ("3" or "4" or "5" or "6"))throw new InvalidOperationException("Selection requires context schema 3..6; regenerate the catalog");
                input.BackupDatabase(copy);
            }
            var result=await Task.Run(()=>TraceSelectionEngine.Select(staging.Path,options,cancellation.Token,progress),cancellation.Token);
            progress("selection_apply",null);
            result.Interest?.Inputs.Verify(cancellation.Token);
            result.Application?.Inputs.Verify(cancellation.Token);
            string profile=Apply(staging.Path,options,result,cancellation.Token);VerifyIntegrity(staging.Path);
            result.Interest?.Inputs.Verify(cancellation.Token);
            string coverage;
            using(var db=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=staging.Path,Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString())) {
                db.Open();using var query=db.CreateCommand();query.CommandText="SELECT value FROM analysis_manifest WHERE key='coverage'";coverage=(string)query.ExecuteScalar()!;
            }
            cancellation.Token.ThrowIfCancellationRequested();string destination=Path.Combine(output,"basic_blocks.sqlite");
            WriteApplicationReport(output,result);
            CatalogPublication.Publish(staging.Path,destination);
            string summary=JsonSerializer.Serialize(new {state="published",qualification_only=true,coverage,database=destination,profile_id=profile,selection=result.Summary,
                database_bytes=new FileInfo(destination).Length,total_seconds=clock.Elapsed.TotalSeconds,peak_working_set_bytes=Process.GetCurrentProcess().PeakWorkingSet64});
            File.WriteAllText(Path.Combine(output,"trace-selection-summary.json"),summary);Console.WriteLine(summary);
            return coverage=="partial"?2:0;
        } finally {Console.CancelKeyPress-=handler;}
    }
}
