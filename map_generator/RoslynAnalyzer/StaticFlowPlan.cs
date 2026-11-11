using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace RoslynAnalyzer;

public sealed record StaticRegion(string Id,string Kind,long Method,long[] Members,string Policy,string Loss);
public sealed record StaticMethodSummary(long Method,string Status,bool Repeated,bool Opaque,int Alternatives,string Emissions,string Evidence);
public sealed record StaticProbeDecision(long Probe,bool Enabled,string Reason,string Evidence);
public sealed record StaticObligation(long Method,string Kind,string Status,string Evidence);

/// <summary>Build-time only. No part of this plan is interpreted by the runtime.</summary>
public sealed class StaticFlowPlan
{
    public const string Algorithm="static_flow_v1";
    public const string Contract="static_probes_v1";
    public List<StaticRegion> Regions {get;}=new();
    public List<StaticMethodSummary> Methods {get;}=new();
    public Dictionary<long,StaticProbeDecision> Decisions {get;}=new();
    public List<StaticObligation> Obligations {get;}=new();
    public Dictionary<long,long[][]> Witnesses {get;}=new();
    public Dictionary<string,string> SourceHashes {get;}=new(StringComparer.OrdinalIgnoreCase);
    public string RepeatPolicy {get;init;}="boundaries";
    public object Summary=>new {algorithm=Algorithm,runtime_contract=Contract,runtime_selection=false,
        repeat_policy=RepeatPolicy,regions=Regions.Count,methods=Methods.Count,
        statuses=Methods.GroupBy(m=>m.Status).ToDictionary(g=>g.Key,g=>g.Count()),
        emission_statuses=Methods.GroupBy(m=>m.Emissions).ToDictionary(g=>g.Key,g=>g.Count()),
        decisions=Decisions.Count,enabled=Decisions.Values.Count(d=>d.Enabled),
        losses=Regions.Select(r=>r.Loss).Distinct(),
        guarantee="ordered marker languages in the declared finite normal-flow abstraction; no runtime activation IDs or loss detection",
        minimum="deterministic greedy reduction; global minimum not claimed"};

    // The grammar permits constant Log statements, braces and an implicit else arm.
    // It deliberately rejects expression replacements and exception wrappers.
    public static bool IsBlindEdit(ApplicationEdit edit) {
        if(edit.Remove!=0)return false;
        string rest=Regex.Replace(edit.Text,@"(?m)^\s*#line (?:hidden|default)\s*$","");
        rest=Regex.Replace(rest,@"AITracer\.Runtime\.TraceContext\.Log\([1-9][0-9]*\);","");
        rest=Regex.Replace(rest,@"\belse\b|[{}\s]","");
        return rest.Length==0;
    }
    public void Persist(SqliteConnection db,SqliteTransaction tx,CancellationToken token) {
        using var c=db.CreateCommand();c.Transaction=tx;
        void Run(string sql,params object[] args){token.ThrowIfCancellationRequested();c.CommandText=sql;c.Parameters.Clear();for(int i=0;i<args.Length;i++)c.Parameters.AddWithValue("@p"+i,args[i]);c.ExecuteNonQuery();}
        Run("""
          CREATE TABLE IF NOT EXISTS static_flow_regions(id TEXT PRIMARY KEY,kind TEXT NOT NULL,method_id INTEGER NOT NULL,members_json TEXT NOT NULL,policy TEXT NOT NULL,loss TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS static_flow_methods(method_id INTEGER PRIMARY KEY REFERENCES methods(id),status TEXT NOT NULL,repeated INTEGER NOT NULL,opaque INTEGER NOT NULL,alternatives INTEGER NOT NULL,emissions TEXT NOT NULL,evidence TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS static_flow_decisions(probe_id INTEGER PRIMARY KEY REFERENCES basic_blocks(id),enabled INTEGER NOT NULL,reason TEXT NOT NULL,evidence TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS static_flow_obligations(id INTEGER PRIMARY KEY,method_id INTEGER NOT NULL REFERENCES methods(id),kind TEXT NOT NULL,status TEXT NOT NULL,evidence TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS static_flow_languages(method_id INTEGER NOT NULL REFERENCES methods(id),first_probe INTEGER NOT NULL,word_json TEXT NOT NULL,PRIMARY KEY(method_id,word_json));
          CREATE INDEX IF NOT EXISTS static_language_start ON static_flow_languages(first_probe);
          CREATE TABLE IF NOT EXISTS static_flow_sources(path TEXT PRIMARY KEY,source_hash TEXT NOT NULL);
          DELETE FROM static_flow_regions;DELETE FROM static_flow_methods;DELETE FROM static_flow_decisions;DELETE FROM static_flow_obligations;DELETE FROM static_flow_languages;
          DELETE FROM static_flow_sources;
          """);
        foreach(var r in Regions)Run("INSERT INTO static_flow_regions VALUES(@p0,@p1,@p2,@p3,@p4,@p5)",r.Id,r.Kind,r.Method,JsonSerializer.Serialize(r.Members),r.Policy,r.Loss);
        foreach(var m in Methods)Run("INSERT INTO static_flow_methods VALUES(@p0,@p1,@p2,@p3,@p4,@p5,@p6)",m.Method,m.Status,m.Repeated?1:0,m.Opaque?1:0,m.Alternatives,m.Emissions,m.Evidence);
        foreach(var d in Decisions.Values)Run("INSERT INTO static_flow_decisions VALUES(@p0,@p1,@p2,@p3)",d.Probe,d.Enabled?1:0,d.Reason,d.Evidence);
        foreach(var (path,hash) in SourceHashes)Run("INSERT INTO static_flow_sources VALUES(@p0,@p1)",path,hash);
        foreach(var o in Obligations)Run("INSERT INTO static_flow_obligations(method_id,kind,status,evidence) VALUES(@p0,@p1,@p2,@p3)",o.Method,o.Kind,o.Status,o.Evidence);
        foreach(var (method,words) in Witnesses)foreach(var word in words.Select(w=>w.Where(id=>Decisions[id].Enabled).ToArray()).Where(w=>w.Length>0).DistinctBy(w=>JsonSerializer.Serialize(w)))
            Run("INSERT INTO static_flow_languages VALUES(@p0,@p1,@p2)",method,word[0],JsonSerializer.Serialize(word));
        Run("INSERT OR REPLACE INTO analysis_manifest VALUES('static_flow_summary',@p0)",JsonSerializer.Serialize(Summary));
        Run("INSERT OR REPLACE INTO analysis_manifest VALUES('injection_contract',@p0)",Contract);
        Run("INSERT OR REPLACE INTO analysis_manifest VALUES('schema_version','8')");
    }
}
