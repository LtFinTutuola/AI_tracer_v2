using System.Globalization;

namespace RoslynAnalyzer;

public sealed record TraceSelectionOptions
{
    public bool Enabled { get; init; } = true;
    public double AmbiguityBudget { get; init; } = .01;
    public int MaxCallDepth { get; init; } = 4;
    public int MaxCandidates { get; init; } = 8;
    public int SamplesPerRoot { get; init; } = 512;
    public double MaxDurationSeconds { get; init; } = 600;
    public int MaxMemoryMb { get; init; } = 512;
    public int Seed { get; init; } = 1729;

    public void Validate()
    {
        if (!double.IsFinite(AmbiguityBudget) || AmbiguityBudget < 0 || AmbiguityBudget > 1)
            throw new ArgumentException("trace_selection.ambiguity_budget must be a finite fraction in [0,1]");
        if (MaxCallDepth < 0 || MaxCallDepth > 64 || MaxCandidates < 1 || SamplesPerRoot < 64 ||
            SamplesPerRoot > 1_000_000 || MaxMemoryMb < 1 || MaxMemoryMb > 16384 ||
            !double.IsFinite(MaxDurationSeconds) || MaxDurationSeconds <= 0)
            throw new ArgumentException("Invalid trace_selection limits: depth 0..64, candidates >=1, samples 64..1000000, memory 1..16384 MB, duration >0");
    }

    public static TraceSelectionOptions ParseOption(TraceSelectionOptions value, string option, string text)
    {
        int Integer() => int.Parse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
        double Number() => double.Parse(text, NumberStyles.Float, CultureInfo.InvariantCulture);
        return option switch {
            "--trace-selection" => value with { Enabled = bool.Parse(text) },
            "--ambiguity-budget" => value with { AmbiguityBudget = Number() },
            "--selection-max-call-depth" => value with { MaxCallDepth = Integer() },
            "--selection-max-candidates" => value with { MaxCandidates = Integer() },
            "--selection-samples-per-root" => value with { SamplesPerRoot = Integer() },
            "--selection-timeout-seconds" => value with { MaxDurationSeconds = Number() },
            "--selection-memory-mb" => value with { MaxMemoryMb = Integer() },
            "--selection-seed" => value with { Seed = Integer() },
            _ => throw new ArgumentException("Unknown option " + option)
        };
    }
}
