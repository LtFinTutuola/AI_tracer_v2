using System;

namespace RoslynAnalyzer
{
    public class BasicBlockRecord
    {
        public int? Id { get; set; }
        public string ProjectName { get; set; }
        public string FilePath { get; set; }
        public string MethodSignature { get; set; }
        public int ScopeStartLine { get; set; }
        public int ScopeEndLine { get; set; }
        public int BlockStartLine { get; set; }
        public int BlockEndLine { get; set; }
        public int InjectionLine { get; set; }
        public int InjectionOffset { get; set; }
        public string Reason { get; set; }
        public bool ToTrace { get; set; } = true;
    }
}
