using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace RoslynAnalyzer;

/// <summary>Stable comparison of legacy records produced for a shared physical source file.</summary>
public sealed record LegacyProjectionRecord(
    string MethodSignature,
    int ScopeStartLine,
    int ScopeEndLine,
    int BlockStartLine,
    int BlockEndLine,
    int InjectionLine,
    int InjectionOffset,
    string Reason,
    bool ToTrace,
    bool WrapInBlock,
    int StatementEndOffset);

public sealed record LegacyProjectionOrigin(
    string ProjectName,
    string ProjectPath,
    string VariantId,
    string RequestedTargetFramework,
    string EffectiveTargetFramework,
    string AssemblyName,
    IReadOnlyList<string> PreprocessorSymbols);

public sealed record LegacyProjectionSnapshot(
    LegacyProjectionOrigin Origin,
    string SourcePath,
    string Hash,
    IReadOnlyList<LegacyProjectionRecord> Records);

public sealed record LegacyProjectionFieldDifference(string Field, string First, string Second);
public sealed record LegacyProjectionDifference(
    int InjectionOffset,
    string Kind,
    IReadOnlyList<LegacyProjectionRecord> First,
    IReadOnlyList<LegacyProjectionRecord> Second,
    IReadOnlyList<LegacyProjectionFieldDifference> Fields);

public sealed class LegacyProjectionConflictException : InvalidOperationException
{
    public LegacyProjectionSnapshot First { get; }
    public LegacyProjectionSnapshot Second { get; }
    public IReadOnlyList<LegacyProjectionDifference> Differences { get; }

    public LegacyProjectionConflictException(
        LegacyProjectionSnapshot first,
        LegacyProjectionSnapshot second,
        IReadOnlyList<LegacyProjectionDifference> differences)
        : base($"Conflicting legacy projections for shared source: {second.SourcePath}. " +
               $"First project={first.Origin.ProjectName}, second project={second.Origin.ProjectName}, " +
               $"first hash={first.Hash}, second hash={second.Hash}, differences={differences.Count}.")
    {
        First = first;
        Second = second;
        Differences = differences;
    }
}

public static class LegacyProjectionDiagnostics
{
    public static LegacyProjectionSnapshot Create(
        Project? project,
        string variantId,
        string requestedTargetFramework,
        string sourcePath,
        IEnumerable<BasicBlockRecord> records)
    {
        var projection = records.Select(record => new LegacyProjectionRecord(
            record.MethodSignature, record.ScopeStartLine, record.ScopeEndLine,
            record.BlockStartLine, record.BlockEndLine, record.InjectionLine,
            record.InjectionOffset, record.Reason, record.ToTrace, record.WrapInBlock,
            record.StatementEndOffset)).OrderBy(record => record.InjectionOffset)
            .ThenBy(record => JsonSerializer.Serialize(record), StringComparer.Ordinal).ToArray();
        string? effectiveTargetFramework = null;
        project?.AnalyzerOptions.AnalyzerConfigOptionsProvider.GlobalOptions
            .TryGetValue("build_property.TargetFramework", out effectiveTargetFramework);
        var parseOptions = project?.ParseOptions as CSharpParseOptions;
        var origin = new LegacyProjectionOrigin(
            project?.Name ?? "<test>",
            project?.FilePath ?? "<in-memory>",
            variantId,
            requestedTargetFramework,
            effectiveTargetFramework ?? "<not-reported>",
            project?.AssemblyName ?? "<unknown>",
            parseOptions?.PreprocessorSymbolNames.OrderBy(symbol => symbol).ToArray() ?? Array.Empty<string>());
        string content = JsonSerializer.Serialize(projection);
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
        return new LegacyProjectionSnapshot(origin, Path.GetFullPath(sourcePath), hash, projection);
    }

    public static IReadOnlyList<LegacyProjectionDifference> Diff(
        LegacyProjectionSnapshot first,
        LegacyProjectionSnapshot second)
    {
        var result = new List<LegacyProjectionDifference>();
        var firstByOffset = first.Records.GroupBy(record => record.InjectionOffset)
            .ToDictionary(group => group.Key, group => group.ToArray());
        var secondByOffset = second.Records.GroupBy(record => record.InjectionOffset)
            .ToDictionary(group => group.Key, group => group.ToArray());
        foreach (int offset in firstByOffset.Keys.Union(secondByOffset.Keys).OrderBy(offset => offset))
        {
            firstByOffset.TryGetValue(offset, out var firstRecords);
            secondByOffset.TryGetValue(offset, out var secondRecords);
            firstRecords ??= Array.Empty<LegacyProjectionRecord>();
            secondRecords ??= Array.Empty<LegacyProjectionRecord>();
            if (JsonSerializer.Serialize(firstRecords) == JsonSerializer.Serialize(secondRecords)) continue;
            var fields = firstRecords.Length == 1 && secondRecords.Length == 1
                ? FieldDiff(firstRecords[0], secondRecords[0])
                : Array.Empty<LegacyProjectionFieldDifference>();
            result.Add(new LegacyProjectionDifference(offset,
                firstRecords.Length == 0 ? "missing_in_first" : secondRecords.Length == 0 ? "missing_in_second" : "different_record",
                firstRecords, secondRecords, fields));
        }
        return result;
    }

    /// <summary>Only a differing record at the same physical injection point is incompatible.</summary>
    public static IReadOnlyList<LegacyProjectionFieldDifference> CompareAtOffset(
        LegacyProjectionRecord first, LegacyProjectionRecord second)
    {
        if(first.InjectionOffset!=second.InjectionOffset)
            throw new ArgumentException("Offsets must match before comparing shared probes");
        return FieldDiff(first,second);
    }

    private static IReadOnlyList<LegacyProjectionFieldDifference> FieldDiff(LegacyProjectionRecord first, LegacyProjectionRecord second)
    {
        var values = new (string Field, object First, object Second)[] {
            (nameof(first.MethodSignature), first.MethodSignature, second.MethodSignature),
            (nameof(first.ScopeStartLine), first.ScopeStartLine, second.ScopeStartLine),
            (nameof(first.ScopeEndLine), first.ScopeEndLine, second.ScopeEndLine),
            (nameof(first.BlockStartLine), first.BlockStartLine, second.BlockStartLine),
            (nameof(first.BlockEndLine), first.BlockEndLine, second.BlockEndLine),
            (nameof(first.InjectionLine), first.InjectionLine, second.InjectionLine),
            (nameof(first.Reason), first.Reason, second.Reason),
            (nameof(first.ToTrace), first.ToTrace, second.ToTrace),
            (nameof(first.WrapInBlock), first.WrapInBlock, second.WrapInBlock),
            (nameof(first.StatementEndOffset), first.StatementEndOffset, second.StatementEndOffset)
        };
        return values.Where(value => !Equals(value.First, value.Second))
            .Select(value => new LegacyProjectionFieldDifference(value.Field,
                JsonSerializer.Serialize(value.First), JsonSerializer.Serialize(value.Second))).ToArray();
    }
}
