using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace RoslynAnalyzer;

internal sealed class SelectionMemoryException : Exception { }
internal sealed class SelectionDeadlineException : Exception { }

internal sealed class SelectionResources(TraceSelectionOptions options,CancellationToken token)
{
    private readonly Stopwatch clock=Stopwatch.StartNew();
    public long Bytes {get;private set;}
    public long PeakBytes {get;private set;}
    public double Seconds=>clock.Elapsed.TotalSeconds;
    public long MaxBytes=>options.MaxMemoryMb*1024L*1024L;
    public double PhaseFraction {get;set;}=.4;
    public bool HasTime {get {token.ThrowIfCancellationRequested();return Seconds<options.MaxDurationSeconds*PhaseFraction;}}
    public void Check() {if(!HasTime)throw new SelectionDeadlineException();}
    public void Reserve(long bytes) {
        token.ThrowIfCancellationRequested();
        if(bytes<0||Bytes+bytes>options.MaxMemoryMb*1024L*1024L)throw new SelectionMemoryException();
        Bytes+=bytes;PeakBytes=Math.Max(Bytes,PeakBytes);
    }
    public void Release(long bytes)=>Bytes-=bytes;
}

internal sealed class SelectionMethod(long id,string key)
{
    public long Id {get;}=id;
    public string Key {get;}=key;
    public List<long> Calls {get;}=new();
    public HashSet<long> Probes {get;}=new();
}
internal sealed class SelectionProbe(long id,bool baseline,string path)
{
    public long Id {get;}=id;
    public bool Baseline {get;}=baseline;
    public string Path {get;}=path;
    public HashSet<long> Variants {get;}=new();
    public HashSet<long> Owners {get;}=new();
}
internal sealed record SelectionEdge(long Id,long Target,bool Modeled,string Alternative);
internal sealed record SelectionPoint(string Kind,long[] Probes,long Site,long Target,string Resolution,int Position,int Continuation);
internal sealed class SelectionNode(long id,int ordinal,string kind)
{
    public long Id {get;}=id;
    public int Ordinal {get;}=ordinal;
    public string Kind {get;}=kind;
    public List<SelectionEdge> Edges {get;}=new();
    public List<SelectionPoint> Points {get;}=new();
}
internal sealed class SelectionGraph
{
    public long Method {get;init;}
    public Dictionary<long,SelectionNode> Nodes {get;}=new();
    public long Entry {get;set;}
    public long Bytes {get;set;}
    public Dictionary<long,SelectionEdge> Prefix {get;}=new();
    public Dictionary<long,SelectionEdge> Suffix {get;}=new();
    public List<SelectionEdge> Goals {get;}=new();
    public long[]? Plan(int index,int seed) {
        if(Goals.Count==0)return null;
        var edge=Goals[(int)(((long)(uint)seed+index)%Goals.Count)];
        var before=new List<long>();long node=edge.Target;
        // Prefix ends at the source of the goal edge (found while indexing).
        long source=Sources[edge.Id];node=source;
        while(node!=Entry) {if(!Prefix.TryGetValue(node,out var previous))return null;before.Add(previous.Id);node=Sources[previous.Id];}
        before.Reverse();before.Add(edge.Id);node=edge.Target;
        while(Nodes[node].Kind!="Exit") {if(!Suffix.TryGetValue(node,out var next))return null;before.Add(next.Id);node=next.Target;}
        return before.ToArray();
    }
    public Dictionary<long,long> Sources {get;}=new();
}

/// <summary>Indexed per-method graph loads; numeric identities retain variant/assembly isolation.</summary>
internal sealed class TraceSelectionModel : IDisposable
{
    private readonly SqliteConnection db;
    private readonly SelectionResources resources;
    private readonly Dictionary<long,(SelectionGraph Graph,LinkedListNode<long> Node)> cache=new();
    private readonly LinkedList<long> lru=new();
    private readonly Dictionary<long,int> inUse=new();
    private long cacheBytes;
    private readonly long cacheLimit;
    public Dictionary<long,SelectionMethod> Methods {get;}=new();
    public Dictionary<long,SelectionProbe> Probes {get;}=new();
    public Dictionary<long,string> Protected {get;}=new();
    public Dictionary<string,long> OpaqueCalls {get;}=new();
    public long Steps {get;private set;}

    public TraceSelectionModel(string path,SelectionResources resources,int memoryMb)
    {
        this.resources=resources;cacheLimit=Math.Max(1024L*1024,memoryMb*1024L*1024/3);
        db=new(new SqliteConnectionStringBuilder {DataSource=path,Mode=SqliteOpenMode.ReadOnly,Pooling=false}.ToString());db.Open();
        using var cmd=db.CreateCommand();cmd.CommandText="PRAGMA cache_size=-1024";cmd.ExecuteNonQuery();resources.Reserve(1024*1024);
    }
    private void Rows(string sql,Action<SqliteDataReader> read,long? method=null)
    {
        using var cmd=db.CreateCommand();cmd.CommandText=sql;if(method!=null)cmd.Parameters.AddWithValue("@method",method);
        using var rows=cmd.ExecuteReader();while(rows.Read()){resources.Check();read(rows);}
    }
    public void Load()
    {
        Rows("SELECT id,stable_key FROM methods WHERE status='analyzed' ORDER BY stable_key,id",row=>{
            resources.Reserve(512);Methods[row.GetInt64(0)]=new(row.GetInt64(0),row.GetString(1));
        });
        Rows("SELECT id,to_trace,file_path FROM basic_blocks ORDER BY id",row=>{
            string path=row.GetString(2);resources.Reserve(640+path.Length*2L);
            Probes[row.GetInt64(0)]=new(row.GetInt64(0),row.GetInt32(1)!=0,path);
        });
        Rows("SELECT l.legacy_id,l.method_id,l.point_id FROM legacy_block_links l ORDER BY l.id",row=>{
            long id=row.GetInt64(0),method=row.GetInt64(1);if(!Probes.TryGetValue(id,out var probe))return;
            resources.Reserve(48);probe.Owners.Add(method);
            if(Methods.TryGetValue(method,out var m))m.Probes.Add(id);
            if(row.IsDBNull(2))Protected.TryAdd(id,"unmapped");
        });
        Rows("SELECT legacy_id,variant_id FROM legacy_probe_variants",row=>{
            resources.Reserve(32);Probes[row.GetInt64(0)].Variants.Add(row.GetInt64(1));
        });
        var files=new Dictionary<string,HashSet<long>>(StringComparer.OrdinalIgnoreCase);
        Rows("SELECT path,variant_id FROM documents WHERE origin='source'",row=>{
            string path=row.GetString(0);resources.Reserve(256+path.Length*2L);
            if(!files.TryGetValue(path,out var variants))files[path]=variants=new();variants.Add(row.GetInt64(1));
        });
        foreach(var probe in Probes.Values) {
            resources.Check();
            if(probe.Owners.Count==0)Protected.TryAdd(probe.Id,"no_mapping");
            if(files.TryGetValue(probe.Path,out var variants)&&!variants.IsSubsetOf(probe.Variants))Protected.TryAdd(probe.Id,"variant_without_selection");
        }
        Rows("SELECT scope FROM analysis_diagnostics WHERE code='SHARED_PROBE_CONFLICT_DISCARDED'",row=>{
            if(long.TryParse(row.GetString(0).Replace("legacy:",""),out long id))Protected.TryAdd(id,"shared_projection_conflict");
        });
        Rows("""
            SELECT s.method_id,min(t.method_id) FROM call_sites s JOIN call_targets t ON t.site_id=s.id
            WHERE s.resolution='static' GROUP BY s.id HAVING count(*)=1
            """,row=>{
            long caller=row.GetInt64(0),target=row.GetInt64(1);
            if(Methods.TryGetValue(caller,out var method)&&Methods.ContainsKey(target)){resources.Reserve(16);method.Calls.Add(target);}
        });
    }
    public HashSet<long> ActiveRoots(int depth)
    {
        var active=Methods.Values.Where(method=>method.Probes.Any(id=>Probes[id].Baseline)).Select(method=>method.Id).ToHashSet();
        for(int level=0;level<depth;level++) {
            resources.Check();var next=new HashSet<long>(active);
            foreach(var method in Methods.Values)if(method.Calls.Any(active.Contains))next.Add(method.Id);
            active=next;
        }
        return active;
    }
    public void ProtectUnqualifiedMethods(IEnumerable<long> seeds)
    {
        // Qualification belongs to the method body. A caller with incomplete
        // control flow must not veto a separately qualified callee's probes.
        // IDs owned by several methods/variants remain globally protected if
        // any of their actual owners is unqualified.
        foreach(long id in seeds) {
            resources.Check();
            if(Methods.TryGetValue(id,out var method))
                foreach(long probe in method.Probes)Protected.TryAdd(probe,"unqualified_method");
        }
    }
    private bool Evict()
    {
        var node=lru.First;while(node!=null&&inUse.ContainsKey(node.Value))node=node.Next;
        if(node==null)return false;
        long id=node.Value;var old=cache[id];cacheBytes-=old.Graph.Bytes;resources.Release(old.Graph.Bytes);cache.Remove(id);lru.Remove(node);return true;
    }
    public void ClearCache(){while(lru.Count>0)if(!Evict())break;}
    public SelectionGraph Graph(long method)
    {
        resources.Check();
        if(cache.TryGetValue(method,out var cached)) {lru.Remove(cached.Node);lru.AddLast(cached.Node);return cached.Graph;}
        var graph=new SelectionGraph {Method=method};
        void Charge(long amount){while(cacheBytes+graph.Bytes+amount>cacheLimit&&lru.Count>0)if(!Evict())break;resources.Reserve(amount);graph.Bytes+=amount;}
        try {
            Rows("SELECT id,ordinal,kind FROM flow_nodes WHERE method_id=@method ORDER BY ordinal",row=>{
                Charge(256);var node=new SelectionNode(row.GetInt64(0),row.GetInt32(1),row.GetString(2));graph.Nodes[node.Id]=node;if(node.Kind=="Entry")graph.Entry=node.Id;
            },method);
            Rows("""
                SELECT e.id,e.source_id,e.target_id,e.status,e.alternative FROM flow_edges e
                JOIN flow_nodes n ON n.id=e.source_id WHERE n.method_id=@method ORDER BY e.id
                """,row=>{
                Charge(128);long id=row.GetInt64(0),source=row.GetInt64(1);graph.Sources[id]=source;
                graph.Nodes[source].Edges.Add(new(id,row.IsDBNull(2)?0:row.GetInt64(2),row.GetString(3)=="modeled",row.GetString(4)));
            },method);
            var calls=new Dictionary<long,(long Id,long Target,string Resolution,int Continuation)>();
            Rows("""
                SELECT s.point_id,s.id,s.resolution,s.continuation_position,count(t.method_id),min(t.method_id)
                FROM call_sites s LEFT JOIN call_targets t ON t.site_id=s.id
                WHERE s.method_id=@method GROUP BY s.id ORDER BY s.id
                """,row=>{
                Charge(128);calls[row.GetInt64(0)]=(row.GetInt64(1),row.GetInt32(4)==1&&!row.IsDBNull(5)?row.GetInt64(5):0,row.GetString(2),row.GetInt32(3));
            },method);
            var links=new Dictionary<long,List<long>>();
            Rows("SELECT point_id,legacy_id FROM legacy_block_links WHERE method_id=@method AND point_id IS NOT NULL ORDER BY id",row=>{
                if(!Probes[row.GetInt64(1)].Baseline)return;
                Charge(48);long point=row.GetInt64(0);if(!links.TryGetValue(point,out var ids))links[point]=ids=new();ids.Add(row.GetInt64(1));
            },method);
            Rows("""
                SELECT p.id,p.node_id,p.position,p.kind FROM flow_points p JOIN flow_nodes n ON n.id=p.node_id
                WHERE n.method_id=@method ORDER BY n.ordinal,p.position
                """,row=>{
                long id=row.GetInt64(0);var call=calls.GetValueOrDefault(id);Charge(160+links.GetValueOrDefault(id)?.Count*8L??160);
                graph.Nodes[row.GetInt64(1)].Points.Add(new(row.GetString(3),links.GetValueOrDefault(id)?.Distinct().ToArray()??Array.Empty<long>(),call.Id,call.Target,call.Resolution??"",row.GetInt32(2),call.Continuation));
            },method);
            if(graph.Entry==0)throw new InvalidOperationException("Analyzed method has no entry: "+method);
            var queue=new Queue<long>();var seen=new HashSet<long>{graph.Entry};queue.Enqueue(graph.Entry);
            while(queue.TryDequeue(out long node))foreach(var edge in graph.Nodes[node].Edges.Where(edge=>edge.Modeled&&edge.Target!=0))
                if(seen.Add(edge.Target)){graph.Prefix[edge.Target]=edge;queue.Enqueue(edge.Target);}
            var reverse=new Dictionary<long,List<SelectionEdge>>();
            foreach(var node in graph.Nodes.Values)foreach(var edge in node.Edges.Where(edge=>edge.Modeled&&edge.Target!=0)) {
                if(!reverse.TryGetValue(edge.Target,out var edges))reverse[edge.Target]=edges=new();edges.Add(edge);
            }
            var exits=graph.Nodes.Values.Where(node=>node.Kind=="Exit").Select(node=>node.Id).ToHashSet();
            queue=new(exits);
            while(queue.TryDequeue(out long node))foreach(var edge in reverse.GetValueOrDefault(node)??new())
                if(exits.Add(graph.Sources[edge.Id])){graph.Suffix[graph.Sources[edge.Id]]=edge;queue.Enqueue(graph.Sources[edge.Id]);}
            foreach(var node in graph.Nodes.Values)if(seen.Contains(node.Id))graph.Goals.AddRange(node.Edges.Where(edge=>edge.Modeled&&edge.Target!=0&&exits.Contains(edge.Target)));
            Charge(graph.Nodes.Count*96L+graph.Goals.Count*24L);
            cache[method]=(graph,lru.AddLast(method));cacheBytes+=graph.Bytes;return graph;
        } catch {resources.Release(graph.Bytes);throw;}
    }
    public (TraceWord? Word,string Status) Sample(long root,int split,int attempt,TraceSelectionOptions options)
    {
        var bytes=SHA256.HashData(Encoding.UTF8.GetBytes($"{options.Seed}:{Methods[root].Key}:{split}:{attempt}"));
        var random=new Random(System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(bytes));
        var events=new List<long>();long allocation=0;int steps=0;
        void Append(long id){resources.Reserve(24);allocation+=24;events.Add(id);}
        string Run(long id,int depth,long[]? plan=null)
        {
            var graph=Graph(id);long node=graph.Entry;int planPosition=0;
            inUse[id]=inUse.GetValueOrDefault(id)+1;
            try {
            var visits=new Dictionary<long,int>();int maxVisits=split==0?3:split==1?4:6;
            while(true) {
                resources.Check();Steps++;steps++;visits[node]=visits.GetValueOrDefault(node)+1;
                if(steps>6000||visits[node]>maxVisits)return "path_budget";
                var current=graph.Nodes[node];
                foreach(var point in current.Points) {
                    resources.Check();
                    if(point.Kind=="incomplete")return "suspension";
                    foreach(long probe in point.Probes)Append(probe);
                    if(point.Site==0)continue;
                    if(point.Resolution=="static"&&point.Target!=0&&Methods.ContainsKey(point.Target)&&depth<options.MaxCallDepth) {
                        string status=Run(point.Target,depth+1);if(status!="normal")return status;
                    } else {string reason=point.Resolution=="static"&&point.Target!=0?"depth_limit":point.Resolution;OpaqueCalls[reason]=OpaqueCalls.GetValueOrDefault(reason)+1;}
                }
                if(current.Kind=="Exit")return "normal";
                if(current.Edges.Count==0)return "dead_end";
                SelectionEdge edge;
                if(plan!=null) {if(planPosition>=plan.Length)return "plan_exhausted";long expected=plan[planPosition++];edge=current.Edges.Single(edge=>edge.Id==expected);}
                else edge=current.Edges[random.Next(current.Edges.Count)];
                if(!edge.Modeled||edge.Target==0)return "incomplete_transfer";
                node=edge.Target;
            }
            } finally {if(--inUse[id]==0)inUse.Remove(id);}
        }
        try {
            var graph=Graph(root);long[]? plan=attempt%2==0?graph.Plan(attempt/2,random.Next()):null;
            string status=Run(root,0,plan);
            return(status=="normal"?new TraceWord(events):null,status);
        } finally {resources.Release(allocation);}
    }
    public void Dispose(){ClearCache();db.Dispose();}
}
