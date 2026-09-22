using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace RoslynAnalyzer
{
    public class TraceableBlock
    {
        public string MethodName { get; set; }
        public string MethodSignature { get; set; }
        public string BlockText { get; set; }
        public int StartLine { get; set; }
        public int ScopeStartLine { get; set; }
        public int ScopeEndLine { get; set; }
        public int InjectionOffset { get; set; }
        public string Reason { get; set; }
    }

    public class BlockExtractor
    {
        public List<TraceableBlock> ExtractBlocks(SemanticModel semanticModel, SyntaxNode syntaxRoot)
        {
            var results = new List<TraceableBlock>();
            var mappedNodes = new HashSet<SyntaxNode>();
            var methods = syntaxRoot.DescendantNodes().OfType<BaseMethodDeclarationSyntax>();

            foreach (var method in methods)
            {
                if (method.Body == null && method.ExpressionBody == null) continue;

                var cfg = ControlFlowGraph.Create(method, semanticModel);
                if (cfg == null) continue;

                var methodName = method.Identifier().Text;
                
                string methodSignature;
                if (method is MethodDeclarationSyntax mds) {
                    methodSignature = mds.WithBody(null).WithExpressionBody(null).ToString().TrimEnd(';', '\r', '\n', ' ');
                } else if (method is ConstructorDeclarationSyntax cds) {
                    methodSignature = cds.WithBody(null).WithExpressionBody(null).ToString().TrimEnd(';', '\r', '\n', ' ');
                } else {
                    methodSignature = methodName;
                }
                
                var methodSpan = syntaxRoot.SyntaxTree.GetLineSpan(method.Span);
                int scopeStartLine = methodSpan.StartLinePosition.Line + 1;
                int scopeEndLine = methodSpan.EndLinePosition.Line + 1;

                bool methodHasBranches = cfg.Blocks.Any(b => b.ConditionalSuccessor != null);

                var branchTargets = new HashSet<BasicBlock>();
                var fallbackTargets = new HashSet<BasicBlock>();

                foreach (var b in cfg.Blocks)
                {
                    if (b.ConditionalSuccessor != null && b.FallThroughSuccessor != null)
                    {
                        var trueBranch = (b.ConditionKind == ControlFlowConditionKind.WhenTrue) 
                                         ? b.ConditionalSuccessor.Destination 
                                         : b.FallThroughSuccessor.Destination;
                                         
                        var falseBranch = (b.ConditionKind == ControlFlowConditionKind.WhenTrue) 
                                          ? b.FallThroughSuccessor.Destination 
                                          : b.ConditionalSuccessor.Destination;

                        if (trueBranch != null) branchTargets.Add(trueBranch);

                        if (falseBranch != null && b.BranchValue != null && b.BranchValue.Syntax != null)
                        {
                            var condSyntax = b.BranchValue.Syntax;
                            bool isExplicitFalse = false;

                            var ifStmt = condSyntax.AncestorsAndSelf().OfType<IfStatementSyntax>().FirstOrDefault();
                            if (ifStmt != null && ifStmt.Else != null)
                            {
                                if (falseBranch.Operations.Any(op => op.Syntax != null && op.Syntax.AncestorsAndSelf().Contains(ifStmt.Else)))
                                {
                                    isExplicitFalse = true;
                                }
                            }

                            var switchStmt = condSyntax.AncestorsAndSelf().OfType<SwitchStatementSyntax>().FirstOrDefault();
                            if (switchStmt != null)
                            {
                                if (falseBranch.Operations.Any(op => op.Syntax != null && op.Syntax.AncestorsAndSelf().OfType<SwitchSectionSyntax>()
                                    .Any(sec => sec.Parent == switchStmt && sec.Labels.Any(l => l is DefaultSwitchLabelSyntax))))
                                {
                                    isExplicitFalse = true;
                                }
                            }

                            if (isExplicitFalse)
                            {
                                branchTargets.Add(falseBranch);
                                fallbackTargets.Add(falseBranch);
                            }
                        }
                    }
                }

                foreach (var block in cfg.Blocks)
                {
                    if (block.Kind == BasicBlockKind.Exit) continue;
                    
                    var ops = block.Operations.Select(o => o.Syntax).ToList();
                    if (block.BranchValue != null) ops.Add(block.BranchValue.Syntax);
                    
                    // Non scartiamo più i blocchi con zero operazioni se sono branch target!
                    // Un return; puro in Roslyn non ha IOperations ma è fondamentale per le Guard Clauses.

                    var statements = new List<SyntaxNode>();
                    CatchClauseSyntax catchNode = null;

                    foreach (var opSyntax in ops)
                    {
                        var enclosing = GetEnclosingTarget(opSyntax);
                        if (enclosing != null && !statements.Contains(enclosing))
                        {
                            statements.Add(enclosing);
                            if (enclosing is CatchClauseSyntax c) catchNode = c;
                        }
                    }

                    // Recupero dei Jump Statement (return, break, ecc.) che chiudono il blocco
                    if (statements.Any())
                    {
                        var lastStmt = statements.LastOrDefault(s => s is StatementSyntax);
                        if (lastStmt is StatementSyntax s)
                        {
                            var nextStmt = GetNextStatement(s);
                            if (nextStmt != null && IsJumpStatement(nextStmt))
                            {
                                if (!statements.Contains(nextStmt))
                                {
                                    statements.Add(nextStmt);
                                }
                            }
                        }
                    }

                    if (!statements.Any()) continue;

                    bool isCatch = catchNode != null;
                    bool isBranchTarget = branchTargets.Contains(block);
                    bool isExplicitFallback = fallbackTargets.Contains(block);
                    bool isExitNode = (block.FallThroughSuccessor != null && block.FallThroughSuccessor.Destination?.Kind == BasicBlockKind.Exit) ||
                                      (block.ConditionalSuccessor != null && block.ConditionalSuccessor.Destination?.Kind == BasicBlockKind.Exit);
                    bool hasJumpStatement = statements.Any(s => s is StatementSyntax stmt && IsJumpStatement(stmt));
                    bool isTerminal = isExitNode || hasJumpStatement;

                    bool isSignificant = isCatch || isBranchTarget || (isTerminal && methodHasBranches);

                    if (!isSignificant) continue;

                    string reason = isCatch ? "Exception Handler (Catch)" :
                                    isExitNode ? "Proof of Completion (Final Exit Block)" :
                                    isExplicitFallback ? "Explicit Fallback (Else/Default)" :
                                    isBranchTarget ? "Branch Target (True/Case Divergence)" :
                                    hasJumpStatement ? "Early Exit (Guard Clause/Jump)" : "Significant Block";

                    string blockText = "";
                    int startLine = 0;
                    int injectionOffset = 0;

                    if (catchNode != null)
                    {
                        var rewriter = new SnippetRewriter(catchNode, new HashSet<SyntaxNode>(statements));
                        var rewritten = rewriter.Visit(catchNode);
                        blockText = rewritten.ToFullString();
                        startLine = syntaxRoot.SyntaxTree.GetLineSpan(catchNode.Span).StartLinePosition.Line + 1;
                        injectionOffset = catchNode.Block.SpanStart + 1;
                    }
                    else
                    {
                        var sb = new StringBuilder();
                        foreach (var stmt in statements)
                        {
                            sb.AppendLine(stmt.ToFullString().Trim());
                            if (startLine == 0)
                            {
                                startLine = syntaxRoot.SyntaxTree.GetLineSpan(stmt.Span).StartLinePosition.Line + 1;
                                injectionOffset = stmt.SpanStart;
                            }
                        }
                        blockText = sb.ToString();
                    }

                    blockText = CleanEmptyLines(blockText);
                    if (string.IsNullOrWhiteSpace(blockText)) continue;

                    results.Add(new TraceableBlock
                    {
                        MethodName = methodName,
                        MethodSignature = methodSignature,
                        BlockText = blockText,
                        StartLine = startLine,
                        ScopeStartLine = scopeStartLine,
                        ScopeEndLine = scopeEndLine,
                        InjectionOffset = injectionOffset,
                        Reason = reason
                    });

                    // Tracciamo tutti i nodi coperti da questo blocco
                    if (catchNode != null)
                    {
                        mappedNodes.Add(catchNode);
                    }
                    foreach (var stmt in statements)
                    {
                        mappedNodes.Add(stmt);
                    }
                }

                // --- FALLBACK SINTATTICO PER GUARD CLAUSES (PURI JUMP) ---
                // Roslyn omette i blocchi composti solo da un return/break dal CFG. 
                // Li recuperiamo analizzando l'albero sintattico.
                var allJumps = method.DescendantNodes().Where(n => n is StatementSyntax s && IsJumpStatement(s)).Cast<StatementSyntax>();
                foreach (var jump in allJumps)
                {
                    if (!mappedNodes.Contains(jump))
                    {
                        bool isCovered = false;
                        var parent = jump.Parent;
                        while (parent != null && parent != method)
                        {
                            if (mappedNodes.Contains(parent))
                            {
                                isCovered = true;
                                break;
                            }
                            parent = parent.Parent;
                        }
                        
                        if (!isCovered)
                        {
                            results.Add(new TraceableBlock
                            {
                                MethodName = methodName,
                                MethodSignature = methodSignature,
                                BlockText = jump.ToFullString().Trim(),
                                StartLine = syntaxRoot.SyntaxTree.GetLineSpan(jump.Span).StartLinePosition.Line + 1,
                                ScopeStartLine = scopeStartLine,
                                ScopeEndLine = scopeEndLine,
                                InjectionOffset = jump.SpanStart,
                                Reason = "Early Exit (Guard Clause/Jump - CFG Fallback)"
                            });
                        }
                    }
                }
            }

            return results.OrderBy(b => b.StartLine).ToList();
        }

        private SyntaxNode GetEnclosingTarget(SyntaxNode node)
        {
            var current = node;
            while (current != null)
            {
                if (current is CatchClauseSyntax catchClause)
                {
                    return catchClause;
                }
                
                if (current is StatementSyntax stmt && !(stmt is BlockSyntax))
                {
                    // Ignoriamo le intestazioni strutturali come richiesto dall'utente
                    if (stmt is IfStatementSyntax || stmt is ForStatementSyntax || 
                        stmt is WhileStatementSyntax || stmt is DoStatementSyntax || 
                        stmt is ForEachStatementSyntax || stmt is TryStatementSyntax ||
                        stmt is SwitchStatementSyntax)
                    {
                        return null; 
                    }
                    return stmt;
                }
                current = current.Parent;
            }
            return null;
        }

        private StatementSyntax GetNextStatement(StatementSyntax stmt)
        {
            if (stmt.Parent is BlockSyntax block)
            {
                var index = block.Statements.IndexOf(stmt);
                if (index >= 0 && index < block.Statements.Count - 1)
                {
                    return block.Statements[index + 1];
                }
            }
            else if (stmt.Parent is SwitchSectionSyntax switchSection)
            {
                var index = switchSection.Statements.IndexOf(stmt);
                if (index >= 0 && index < switchSection.Statements.Count - 1)
                {
                    return switchSection.Statements[index + 1];
                }
            }
            return null;
        }

        private bool IsJumpStatement(StatementSyntax stmt)
        {
            return stmt is ReturnStatementSyntax || stmt is BreakStatementSyntax || 
                   stmt is ContinueStatementSyntax || stmt is ThrowStatementSyntax || 
                   stmt is GotoStatementSyntax || stmt is YieldStatementSyntax;
        }

        private string CleanEmptyLines(string text)
        {
            var lines = text.Split(new[] { "\r\n", "\r", "\n" }, System.StringSplitOptions.None);
            var nonEmpty = lines.Where(l => !string.IsNullOrWhiteSpace(l));
            return string.Join("\n", nonEmpty).Trim();
        }
    }

    class SnippetRewriter : CSharpSyntaxRewriter
    {
        private readonly CatchClauseSyntax _catchNode;
        private readonly HashSet<SyntaxNode> _statementsToKeep;

        public SnippetRewriter(CatchClauseSyntax catchNode, HashSet<SyntaxNode> statementsToKeep)
        {
            _catchNode = catchNode;
            _statementsToKeep = statementsToKeep;
        }

        public override SyntaxNode Visit(SyntaxNode node)
        {
            if (node == null) return null;

            if (node is StatementSyntax stmt && !(stmt is BlockSyntax) && node.Parent != null)
            {
                // Manteniamo solo gli statement richiesti all'interno del blocco catch
                if (stmt.Parent == _catchNode.Block)
                {
                    if (!_statementsToKeep.Contains(stmt))
                    {
                        return null;
                    }
                }
            }

            return base.Visit(node);
        }
    }

    public static class SyntaxExtensions
    {
        public static SyntaxToken Identifier(this BaseMethodDeclarationSyntax method)
        {
            if (method is MethodDeclarationSyntax m) return m.Identifier;
            if (method is ConstructorDeclarationSyntax c) return c.Identifier;
            if (method is DestructorDeclarationSyntax d) return d.Identifier;
            return default;
        }
    }
}
