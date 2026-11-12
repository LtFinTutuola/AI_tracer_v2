using Microsoft.CodeAnalysis;

namespace RoslynAnalyzer;

internal static class ProjectFramework
{
    internal static string Effective(Project project,string requested)
    {
        var options=project.AnalyzerOptions.AnalyzerConfigOptionsProvider.GlobalOptions;
        foreach(string property in new[]{"build_property.TargetFramework","build_property.TargetFrameworkVersion"})
            if(options.TryGetValue(property,out string? value)&&!string.IsNullOrWhiteSpace(value))return value;
        // This is intentionally descriptive rather than a synthetic framework.
        // References on Project are still the authoritative compilation inputs.
        return requested.Equals("auto",StringComparison.OrdinalIgnoreCase)?"<not-reported>":requested;
    }

    internal static bool IsGenerated(Project project,Document document)
    {
        if(string.IsNullOrWhiteSpace(document.FilePath)||string.IsNullOrWhiteSpace(project.FilePath))return false;
        string path=Path.GetFullPath(document.FilePath);
        string projectDirectory=Path.GetDirectoryName(Path.GetFullPath(project.FilePath))!;
        // SDK-generated Compile items may be returned as ordinary Documents (not
        // SourceGeneratedDocument) by MSBuildWorkspace. Files inside the project's
        // intermediate tree are catalogued for semantic completeness but must
        // never become physical injection candidates.
        if(IsUnder(path,Path.Combine(projectDirectory,"obj")))return true;
        var options=project.AnalyzerOptions.AnalyzerConfigOptionsProvider.GlobalOptions;
        foreach(string property in new[]{"build_property.BaseIntermediateOutputPath","build_property.IntermediateOutputPath"})
            if(options.TryGetValue(property,out string? value)&&!string.IsNullOrWhiteSpace(value)) {
                string root=Path.IsPathRooted(value)?value:Path.Combine(projectDirectory,value);
                if(IsUnder(path,root))return true;
            }
        return false;
    }

    private static bool IsUnder(string path,string root)
    {
        string canonicalRoot=Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar,Path.AltDirectorySeparatorChar)+Path.DirectorySeparatorChar;
        return path.StartsWith(canonicalRoot,StringComparison.OrdinalIgnoreCase);
    }
}
