using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.Data.Sqlite;

namespace RoslynAnalyzer;

/// <summary>Document-local source/CFG index. No second CFG and no transitive paths.</summary>
internal sealed class ApplicationFactMapper
{
    private sealed record Point(long Node,int Position,string Kind,int Start,int Length);
    private sealed record Edge(long Id,long Node,string Alternative);
    private sealed record Location(long Node,int Position,long? Edge,string Phase);
    private readonly SqliteConnection db; private readonly SqliteTransaction? tx;
    private readonly SemanticModel model; private readonly CancellationToken token;
    private readonly ControlFlowGraph? graph;
    private readonly List<Point> points=new();
    private readonly Dictionary<int,long> nodeIds=new();
    private readonly Dictionary<long,List<Edge>> edges=new();
    public ApplicationFactMapper(SqliteConnection db,SqliteTransaction? tx,long method,ControlFlowGraph? graph,SemanticModel model,CancellationToken token) {
        this.db=db;this.tx=tx;this.graph=graph;this.model=model;this.token=token;
        using var c=db.CreateCommand();c.Transaction=tx;
        c.CommandText="SELECT p.node_id,p.position,p.kind,p.start,p.length,n.ordinal FROM flow_points p JOIN flow_nodes n ON n.id=p.node_id WHERE n.method_id=@m AND n.reachable=1 ORDER BY n.ordinal,p.position";c.Parameters.AddWithValue("@m",method);
        using(var r=c.ExecuteReader())while(r.Read()){points.Add(new(r.GetInt64(0),r.GetInt32(1),r.GetString(2),r.GetInt32(3),r.GetInt32(4)));nodeIds[r.GetInt32(5)]=r.GetInt64(0);}
        c.CommandText="SELECT e.id,e.source_id,e.alternative FROM flow_edges e JOIN flow_nodes n ON n.id=e.source_id WHERE n.method_id=@m AND n.reachable=1";
        using(var r=c.ExecuteReader())while(r.Read()) {long n=r.GetInt64(1);if(!edges.TryGetValue(n,out var list))edges[n]=list=new();list.Add(new(r.GetInt64(0),n,r.GetString(2)));}
    }
    public void Save(long fact,string kind,SyntaxNode syntax,JsonElement payload) {
        token.ThrowIfCancellationRequested();var locations=new List<Location>();string reason="No demonstrated source/CFG frontier";
        bool unreachable=false;
        if(graph!=null&&kind=="arm"&&syntax is IfStatementSyntax guard) {
            bool truth=payload.GetProperty("truth").GetBoolean();
            var constant=model.GetConstantValue(guard.Condition,token);
            unreachable=constant.HasValue&&constant.Value is bool value&&value!=truth;
            if(!unreachable) {
                var terminal=Decision(guard.Condition,truth);
                if(terminal!=null)locations.AddRange(terminal);
                else reason="Condition lowering has no complete supported boolean frontier";
            }
        } else if(graph!=null&&kind=="case"&&syntax is SwitchSectionSyntax section&&section.Statements.FirstOrDefault() is { } first) {
            locations.AddRange(Statement(first,"before"));
        } else if(graph!=null&&kind is "assignment" or "call") {
            var statement=syntax.AncestorsAndSelf().OfType<ExpressionStatementSyntax>().FirstOrDefault();
            if(statement!=null&&payload.GetProperty("style").GetString()!="unsupported") {
                locations.AddRange(Statement(statement,"before"));
                locations.AddRange(Statement(statement,"after"));
                // A partial statement pair is not evidence of statement completion.
                if(!locations.Any(l=>l.Phase=="before")||!locations.Any(l=>l.Phase=="after"))locations.Clear();
            }
        }
        var distinct=locations.Distinct().ToArray();
        using var c=db.CreateCommand();c.Transaction=tx;
        c.CommandText="INSERT OR REPLACE INTO application_fact_mappings VALUES(@f,@s,@r)";
        c.Parameters.AddWithValue("@f",fact);c.Parameters.AddWithValue("@s",unreachable?"unreachable":distinct.Length>0?"exact_frontier":"source_only");
        c.Parameters.AddWithValue("@r",unreachable?"Constant condition excludes this arm":distinct.Length>0?"Semantic source/CFG boundary":reason);c.ExecuteNonQuery();
        c.Parameters.Clear();c.CommandText="DELETE FROM application_fact_locations WHERE fact_id=@f";c.Parameters.AddWithValue("@f",fact);c.ExecuteNonQuery();
        foreach(var l in distinct) {
            c.Parameters.Clear();c.CommandText="INSERT INTO application_fact_locations(fact_id,node_id,position,edge_id,phase) VALUES(@f,@n,@p,@e,@h)";
            c.Parameters.AddWithValue("@f",fact);c.Parameters.AddWithValue("@n",l.Node);c.Parameters.AddWithValue("@p",l.Position);c.Parameters.AddWithValue("@e",(object?)l.Edge??DBNull.Value);c.Parameters.AddWithValue("@h",l.Phase);c.ExecuteNonQuery();
        }
    }
    private List<Location>? Decision(ExpressionSyntax expression,bool truth) {
        token.ThrowIfCancellationRequested();
        if(expression is ParenthesizedExpressionSyntax paren)return Decision(paren.Expression,truth);
        var operation=model.GetOperation(expression,token);
        if(operation is IUnaryOperation {OperatorKind:UnaryOperatorKind.Not,OperatorMethod:null,Type.SpecialType:SpecialType.System_Boolean}&&expression is PrefixUnaryExpressionSyntax not)
            return Decision(not.Operand,!truth);
        if(operation is IBinaryOperation {OperatorMethod:null,Type.SpecialType:SpecialType.System_Boolean} binary&&expression is BinaryExpressionSyntax syntax) {
            bool and=binary.OperatorKind==BinaryOperatorKind.ConditionalAnd,or=binary.OperatorKind==BinaryOperatorKind.ConditionalOr;
            if(and||or) {
                var right=Decision(syntax.Right,truth);
                if(and&&truth||or&&!truth)return right;
                var left=Decision(syntax.Left,truth);
                return left==null||right==null?null:left.Concat(right).Distinct().ToList();
            }
        }
        if(operation?.Type?.SpecialType!=SpecialType.System_Boolean)return null;
        var matches=points.Where(p=>p.Kind=="control"&&p.Start==expression.SpanStart&&p.Length==expression.Span.Length).ToArray();
        if(matches.Length!=1)return null;
        var e=edges.GetValueOrDefault(matches[0].Node)?.Where(e=>e.Alternative==(truth?"true":"false")).ToArray();
        return e is {Length:1}?new(){new(matches[0].Node,int.MaxValue,e[0].Id,"decision")}:null;
    }
    private IEnumerable<Location> Statement(StatementSyntax statement,string phase) {
        if(phase=="before") {
            // Evaluation can begin in captures/branches well before the final
            // expression statement (e.g. Sink(flag ? F() : G())). Find its CFG
            // entry, not the final call's source_before marker.
            var fragments=graph!.Blocks.Where(b=>b.IsReachable).Select(b=>(Block:b,Operations:b.Operations.Concat(b.BranchValue==null?Array.Empty<IOperation>():new[]{b.BranchValue})
                .Where(op=>statement.Span.Contains(op.Syntax.Span)).ToArray())).Where(x=>x.Operations.Length>0).ToArray();
            var ordinals=fragments.Select(f=>f.Block.Ordinal).ToHashSet();
            var entries=fragments.Where(f=>f.Block.Predecessors.Any(p=>!ordinals.Contains(p.Source.Ordinal))||f.Block.Kind==BasicBlockKind.Entry).ToArray();
            if(entries.Length==1&&nodeIds.TryGetValue(entries[0].Block.Ordinal,out long node)) {
                int start=entries[0].Operations[0].Syntax.SpanStart;
                var first=points.FirstOrDefault(p=>p.Node==node&&p.Kind=="source_before"&&p.Start==start);
                if(first!=null)return new[]{new Location(first.Node,first.Position,null,phase)};
            }
        }
        // Match actual CFG top-level operations belonging to this exact statement,
        // rather than picking a nearby source offset or a capture subexpression.
        var roots=graph!.Blocks.SelectMany(b=>b.Operations).Where(op=>op.Syntax==statement||
            statement is ExpressionStatementSyntax s&&op.Syntax==s.Expression).ToArray();
        if(phase=="after"&&roots.Length==1) {
            var root=roots[0];string kind=phase=="before"?"source_before":"source_after";
            int offset=phase=="before"?root.Syntax.SpanStart:root.Syntax.Span.End;
            var found=points.Where(p=>p.Kind==kind&&p.Start==offset).ToArray();
            if(found.Length==1)return new[]{new Location(found[0].Node,found[0].Position,null,phase)};
        }
        if(phase=="before") {
            var jump=points.Where(p=>p.Kind=="legacy"&&p.Start==statement.SpanStart).ToArray();
            if(jump.Length==1)return new[]{new Location(jump[0].Node,jump[0].Position,null,phase)};
        }
        return Array.Empty<Location>();
    }
}
