using Microsoft.Data.Sqlite;

namespace RoslynAnalyzer;

internal sealed class StaticFlowNode(long id,long method,string kind)
{
    public long Id=id,Method=method;
    public string Kind=kind;
    public List<StaticFlowEdge> Edges=new();
    public List<StaticFlowEvent> Events=new();
}
internal sealed record StaticFlowEdge(long Id,long Source,long Target,bool Complete);
internal sealed record StaticFlowCall(long Site,long Node,int Position,long Caller,string Resolution,long[] Targets);
internal sealed record StaticFlowEvent(int Position,long Probe,long Callee=0);

/// <summary>Compact graph shared by local analysis and context-sensitive call substitution.</summary>
internal sealed class StaticFlowModel
{
    public Dictionary<long,StaticFlowNode> Nodes=new();
    public Dictionary<long,List<long>> MethodNodes=new();
    public Dictionary<long,HashSet<long>> Calls=new();
    public Dictionary<long,StaticFlowCall> Sites=new();
    public Dictionary<long,HashSet<long>> Owners=new();
    public Dictionary<long,List<(long Node,int Position)>> Links=new();
    public HashSet<long> Opaque=new(),OpenCalls=new(),CyclicNodes=new(),Recursive=new(),Repeated=new();
    public Dictionary<long,long> Components=new();
    public List<long[]> MethodComponents=new();

    // Iterative Kosaraju: neither call-chain depth nor the CLR stack limits analysis.
    internal static List<long[]> Scc(IEnumerable<long> vertices,Func<long,IEnumerable<long>> next,Action check)
    {
        var set=vertices.ToHashSet();var seen=new HashSet<long>();var order=new List<long>();
        var reverse=set.ToDictionary(x=>x,x=>new List<long>());
        foreach(long v in set){check();foreach(long w in next(v))if(set.Contains(w))reverse[w].Add(v);}
        foreach(long v in set.OrderBy(x=>x)) {
            if(seen.Contains(v))continue;
            var pending=new Stack<(long Node,bool Leave)>();pending.Push((v,false));
            while(pending.TryPop(out var frame)) {
                check();if(frame.Leave){order.Add(frame.Node);continue;}
                if(!seen.Add(frame.Node))continue;
                pending.Push((frame.Node,true));foreach(long w in next(frame.Node).Reverse())if(set.Contains(w)&&!seen.Contains(w))pending.Push((w,false));
            }
        }
        seen.Clear();var result=new List<long[]>();
        for(int i=order.Count-1;i>=0;i--) {
            long v=order[i];if(!seen.Add(v))continue;
            var members=new List<long>();var pending=new Stack<long>();pending.Push(v);
            while(pending.TryPop(out long n)){check();members.Add(n);foreach(long w in reverse[n])if(seen.Add(w))pending.Push(w);}
            result.Add(members.OrderBy(x=>x).ToArray());
        }
        return result;
    }
    internal static StaticFlowModel Load(SqliteConnection db,IEnumerable<long> methods,SelectionResources resources)
    {
        var model=new StaticFlowModel();foreach(long id in methods){model.MethodNodes[id]=new();model.Calls[id]=new();}
        void Rows(string sql,Action<SqliteDataReader> read){using var c=db.CreateCommand();c.CommandText=sql;using var r=c.ExecuteReader();while(r.Read()){resources.Check();read(r);}}
        Rows("SELECT id,method_id,kind FROM flow_nodes WHERE reachable=1 ORDER BY id",r=>{
            long method=r.GetInt64(1);if(!model.MethodNodes.ContainsKey(method))return;resources.Reserve(256);
            var n=new StaticFlowNode(r.GetInt64(0),method,r.GetString(2));model.Nodes[n.Id]=n;model.MethodNodes[method].Add(n.Id);
        });
        Rows("SELECT id,source_id,target_id,status FROM flow_edges ORDER BY id",r=>{
            if(!model.Nodes.TryGetValue(r.GetInt64(1),out var n))return;resources.Reserve(96);
            long target=r.IsDBNull(2)?0:r.GetInt64(2);bool complete=r.GetString(3)=="modeled"&&model.Nodes.ContainsKey(target);
            n.Edges.Add(new(r.GetInt64(0),n.Id,target,complete));if(!complete)model.Opaque.Add(n.Method);
        });
        var targets=new Dictionary<long,List<long>>();
        Rows("SELECT site_id,method_id FROM call_targets ORDER BY site_id,method_id",r=>{resources.Reserve(64);long site=r.GetInt64(0);if(!targets.TryGetValue(site,out var list))targets[site]=list=new();list.Add(r.GetInt64(1));});
        Rows("SELECT s.id,s.method_id,s.resolution,p.node_id,p.position FROM call_sites s JOIN flow_points p ON p.id=s.point_id ORDER BY s.id",r=>{
            long caller=r.GetInt64(1),node=r.GetInt64(3);if(!model.Nodes.ContainsKey(node))return;resources.Reserve(256);
            var call=new StaticFlowCall(r.GetInt64(0),node,r.GetInt32(4),caller,r.GetString(2),targets.GetValueOrDefault(r.GetInt64(0))?.ToArray()??Array.Empty<long>());
            model.Sites[call.Site]=call;
            foreach(long target in call.Targets)if(model.Calls.ContainsKey(target))model.Calls[caller].Add(target);
            if(call.Resolution!="static"||call.Targets.Length!=1||!model.Calls.ContainsKey(call.Targets[0]))model.OpenCalls.Add(caller);
            else model.Nodes[node].Events.Add(new(call.Position,0,call.Targets[0]));
        });
        Rows("SELECT l.legacy_id,l.method_id,p.node_id,p.position FROM legacy_block_links l LEFT JOIN flow_points p ON p.id=l.point_id ORDER BY l.id",r=>{
            long probe=r.GetInt64(0),method=r.GetInt64(1);if(!model.Owners.TryGetValue(probe,out var own))model.Owners[probe]=own=new();own.Add(method);resources.Reserve(96);
            if(r.IsDBNull(2)||!model.Nodes.ContainsKey(r.GetInt64(2)))return;
            if(!model.Links.TryGetValue(probe,out var links))model.Links[probe]=links=new();links.Add((r.GetInt64(2),r.GetInt32(3)));
        });
        Rows("SELECT DISTINCT m.id FROM methods m JOIN analysis_diagnostics d ON d.scope='method:'||m.id OR d.scope='document:'||m.document_id",r=>model.Opaque.Add(r.GetInt64(0)));
        foreach(var component in Scc(model.Nodes.Keys,n=>model.Nodes[n].Edges.Where(e=>e.Complete).Select(e=>e.Target),resources.Check)) {
            long representative=component[0];foreach(long n in component)model.Components[n]=representative;
            if(component.Length>1||model.Nodes[representative].Edges.Any(e=>e.Target==representative))model.CyclicNodes.UnionWith(component);
        }
        model.MethodComponents=Scc(model.Calls.Keys,m=>model.Calls[m],resources.Check);
        foreach(var component in model.MethodComponents)if(component.Length>1||model.Calls[component[0]].Contains(component[0]))model.Recursive.UnionWith(component);
        model.Repeated.UnionWith(model.Recursive);
        foreach(var call in model.Sites.Values)if(model.CyclicNodes.Contains(call.Node))model.Repeated.UnionWith(call.Targets.Where(model.Calls.ContainsKey));
        var queue=new Queue<long>(model.Repeated);
        while(queue.TryDequeue(out long caller)){resources.Check();foreach(long callee in model.Calls[caller])if(model.Repeated.Add(callee))queue.Enqueue(callee);}
        return model;
    }
}
