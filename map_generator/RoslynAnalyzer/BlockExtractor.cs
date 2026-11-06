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
        public int BlockStartLine { get; set; }
        public int BlockEndLine { get; set; }
        public int InjectionOffset { get; set; }
        public string Reason { get; set; }
        public bool WrapInBlock { get; set; } = false;
        public int StatementEndOffset { get; set; } = 0;
        // Context-only evidence; never changes legacy probe selection.
        public int? CfgOrdinal { get; set; }
    }

    public class BlockExtractor
    {
        public List<TraceableBlock> ExtractBlocks(SemanticModel semanticModel, SyntaxNode syntaxRoot,
            Func<BaseMethodDeclarationSyntax, ControlFlowGraph?>? graphProvider = null)
        {
            var results = new List<TraceableBlock>();
            var mappedNodes = new HashSet<SyntaxNode>();
            var methods = syntaxRoot.DescendantNodes().OfType<BaseMethodDeclarationSyntax>();

            foreach (var method in methods)
            {
                if (method.Body == null && method.ExpressionBody == null) continue;

                ControlFlowGraph cfg = null;
                try
                {
                    cfg = graphProvider == null ? ControlFlowGraph.Create(method, semanticModel) : graphProvider(method);
                }
                catch (Exception ex)
                {
                    // Ignore Roslyn bugs or malformed code that crashes CFG generation
                    continue;
                }

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
                var methodBlocksByOffset = new Dictionary<int, TraceableBlock>();

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

                    // Semantic priority: Branch divergence takes precedence over exit status
                    string reason;
                    if (isCatch)
                    {
                        reason = "Exception Handler (Catch)";
                    }
                    else if (isBranchTarget)
                    {
                        reason = "Branch Target (True/Case Divergence)";
                    }
                    else if (isExplicitFallback)
                    {
                        reason = "Explicit Fallback (Else/Default)";
                    }
                    else if (hasJumpStatement && !isExitNode)
                    {
                        reason = "Early Exit (Guard Clause/Jump)";
                    }
                    else if (isExitNode)
                    {
                        reason = "Proof of Completion (Final Exit Block)";
                    }
                    else if (hasJumpStatement)
                    {
                        reason = "Early Exit (Guard Clause/Jump)";
                    }
                    else
                    {
                        reason = "Significant Block";
                    }

                    string blockText = "";
                    int startLine = 0;
                    int injectionOffset = 0;
                    int blockStartLine = 0;
                    int blockEndLine = 0;
                    
                    var logicalParent = statements.SelectMany(s => s.AncestorsAndSelf())
                        .FirstOrDefault(n => n is BlockSyntax || n is SwitchSectionSyntax);
                        
                    if (logicalParent != null)
                    {
                        blockStartLine = syntaxRoot.SyntaxTree.GetLineSpan(logicalParent.Span).StartLinePosition.Line + 1;
                        blockEndLine = syntaxRoot.SyntaxTree.GetLineSpan(logicalParent.Span).EndLinePosition.Line + 1;
                    }
                    else if (catchNode != null && catchNode.Block != null)
                    {
                        blockStartLine = syntaxRoot.SyntaxTree.GetLineSpan(catchNode.Block.Span).StartLinePosition.Line + 1;
                        blockEndLine = syntaxRoot.SyntaxTree.GetLineSpan(catchNode.Block.Span).EndLinePosition.Line + 1;
                    }
                    else
                    {
                        var firstStmt = statements.FirstOrDefault();
                        if (firstStmt != null)
                        {
                            blockStartLine = syntaxRoot.SyntaxTree.GetLineSpan(firstStmt.Span).StartLinePosition.Line + 1;
                            var lastStmt = statements.LastOrDefault();
                            blockEndLine = syntaxRoot.SyntaxTree.GetLineSpan(lastStmt.Span).EndLinePosition.Line + 1;
                        }
                    }

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

                    bool wrapInBlock = false;
                    int statementEndOffset = 0;
                    var firstStatement = statements.FirstOrDefault();
                    if (firstStatement is StatementSyntax ss && RequiresBlockWrapping(ss))
                    {
                        wrapInBlock = true;
                        statementEndOffset = ss.Span.End;
                    }

                    // Intra-method deduplication: coalesce multiple micro-blocks targeting the same injection offset
                    if (methodBlocksByOffset.TryGetValue(injectionOffset, out var existingBlock))
                    {
                        if (GetReasonPriority(reason) > GetReasonPriority(existingBlock.Reason))
                        {
                            existingBlock.Reason = reason;
                        }
                        if (!existingBlock.WrapInBlock && wrapInBlock)
                        {
                            existingBlock.WrapInBlock = true;
                            existingBlock.StatementEndOffset = statementEndOffset;
                        }
                    }
                    else
                    {
                        methodBlocksByOffset[injectionOffset] = new TraceableBlock
                        {
                            MethodName = methodName,
                            MethodSignature = methodSignature,
                            BlockText = blockText,
                            StartLine = startLine,
                            ScopeStartLine = scopeStartLine,
                            ScopeEndLine = scopeEndLine,
                            BlockStartLine = blockStartLine,
                            BlockEndLine = blockEndLine,
                            InjectionOffset = injectionOffset,
                            Reason = reason,
                            WrapInBlock = wrapInBlock,
                            StatementEndOffset = statementEndOffset,
                            CfgOrdinal = block.Ordinal
                        };
                    }

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
                var allJumps = method.DescendantNodes(n => n is not LocalFunctionStatementSyntax && n is not AnonymousFunctionExpressionSyntax).Where(n => n is StatementSyntax s && IsJumpStatement(s)).Cast<StatementSyntax>();
                foreach (var jump in allJumps)
                {
                    if (!mappedNodes.Contains(jump) && !methodBlocksByOffset.ContainsKey(jump.SpanStart))
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
                            bool jumpWrap = RequiresBlockWrapping(jump);
                            methodBlocksByOffset[jump.SpanStart] = new TraceableBlock
                            {
                                MethodName = methodName,
                                MethodSignature = methodSignature,
                                BlockText = jump.ToFullString().Trim(),
                                StartLine = syntaxRoot.SyntaxTree.GetLineSpan(jump.Span).StartLinePosition.Line + 1,
                                ScopeStartLine = scopeStartLine,
                                ScopeEndLine = scopeEndLine,
                                BlockStartLine = syntaxRoot.SyntaxTree.GetLineSpan(jump.Span).StartLinePosition.Line + 1,
                                BlockEndLine = syntaxRoot.SyntaxTree.GetLineSpan(jump.Span).EndLinePosition.Line + 1,
                                InjectionOffset = jump.SpanStart,
                                Reason = "Early Exit (Guard Clause/Jump - CFG Fallback)",
                                WrapInBlock = jumpWrap,
                                StatementEndOffset = jumpWrap ? jump.Span.End : 0
                            };
                        }
                    }
                }

                results.AddRange(methodBlocksByOffset.Values);
            }

            return results.OrderBy(b => b.StartLine).ToList();
        }

        private static bool RequiresBlockWrapping(StatementSyntax stmt)
        {
            if (stmt == null || stmt is BlockSyntax) return false;

            var parent = stmt.Parent;
            if (parent is IfStatementSyntax ifStmt && ifStmt.Statement == stmt)
                return true;
            if (parent is ElseClauseSyntax elseClause && elseClause.Statement == stmt)
                return true;
            if (parent is WhileStatementSyntax whileStmt && whileStmt.Statement == stmt)
                return true;
            if (parent is ForStatementSyntax forStmt && forStmt.Statement == stmt)
                return true;
            if (parent is ForEachStatementSyntax forEachStmt && forEachStmt.Statement == stmt)
                return true;
            if (parent is DoStatementSyntax doStmt && doStmt.Statement == stmt)
                return true;

            return false;
        }

        private static int GetReasonPriority(string reason)
        {
            switch (reason)
            {
                case "Exception Handler (Catch)": return 6;
                case "Branch Target (True/Case Divergence)": return 5;
                case "Explicit Fallback (Else/Default)": return 4;
                case "Early Exit (Guard Clause/Jump)": return 3;
                case "Early Exit (Guard Clause/Jump - CFG Fallback)": return 3;
                case "Proof of Completion (Final Exit Block)": return 2;
                default: return 1;
            }
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
