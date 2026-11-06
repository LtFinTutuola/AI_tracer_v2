namespace RoslynAnalyzer;

/// <summary>Hashing is an index only: equality always checks all ordered IDs.</summary>
public sealed class TraceWord : IEquatable<TraceWord>
{
    public long[] Events { get; }
    private readonly int hash;
    public TraceWord(IEnumerable<long> events)
    {
        Events = events.ToArray();
        unchecked { uint h=2166136261; foreach(long value in Events) { h=(h^(uint)value)*16777619;h=(h^(uint)(value>>32))*16777619; } hash=(int)h; }
    }
    public bool Equals(TraceWord? other) => other!=null && Events.AsSpan().SequenceEqual(other.Events);
    public override bool Equals(object? other) => other is TraceWord word && Equals(word);
    public override int GetHashCode() => hash;
}

public sealed record TraceObservation(TraceWord Word, long Training, long Calibration);
public sealed record TraceOptimization(HashSet<long> Disabled, long TrainingAmbiguous, long CalibrationAmbiguous,
    int MaximumCandidates, long EventsBefore, long EventsAfter, bool TimeLimited);

/// <summary>Incremental partition coarsening. No pairwise path matrix or global path enumeration.</summary>
public static class TraceSequenceSelector
{
    private sealed record Group(TraceWord Word,int Classes,long Training,long Calibration);
    private static long Bytes(Group group)=>256L+group.Word.Events.Length*64L;

    public static TraceOptimization Select(IEnumerable<TraceObservation> observations, ISet<long> protectedIds,
        double epsilon, int maxCandidates, Func<bool>? timeRemaining=null, Action<long>? reserve=null,
        Action<long>? release=null, CancellationToken token=default)
    {
        if(!double.IsFinite(epsilon)||epsilon<0||epsilon>1||maxCandidates<1)throw new ArgumentException("Invalid selection budget");
        var merged=new Dictionary<TraceWord,(long Training,long Calibration)>();
        foreach(var row in observations) {
            token.ThrowIfCancellationRequested();
            if(timeRemaining!=null&&!timeRemaining())return new(new(),0,0,0,0,0,true);
            if(row.Training<0||row.Calibration<0)throw new ArgumentException("Negative observation count");
            var old=merged.GetValueOrDefault(row.Word);
            merged[row.Word]=(checked(old.Training+row.Training),checked(old.Calibration+row.Calibration));
        }
        var groups=new Dictionary<TraceWord,Group>();
        var index=new Dictionary<long,HashSet<TraceWord>>();
        var frequencies=new Dictionary<long,long>();long owned=0;
        void Charge(long bytes) { reserve?.Invoke(bytes);owned+=bytes; }
        void Free(long bytes) {release?.Invoke(bytes);owned-=bytes;}
        void Add(Group group) {
            Charge(Bytes(group));groups.Add(group.Word,group);
            foreach(long id in group.Word.Events.Distinct()) {
                if(!index.TryGetValue(id,out var words))index[id]=words=new();
                words.Add(group.Word);
            }
        }
        void Remove(Group group) {
            groups.Remove(group.Word);
            foreach(long id in group.Word.Events.Distinct())index[id].Remove(group.Word);
            Free(Bytes(group));
        }
        try {
            long training=0,calibration=0,before=0;
            foreach(var (word,counts) in merged) {
                token.ThrowIfCancellationRequested();
                if(timeRemaining!=null&&!timeRemaining())return new(new(),0,0,0,0,0,true);
                training=checked(training+counts.Training);calibration=checked(calibration+counts.Calibration);
                Add(new(word,1,counts.Training,counts.Calibration));
                foreach(long id in word.Events) {frequencies[id]=checked(frequencies.GetValueOrDefault(id)+counts.Training+counts.Calibration);before+=counts.Training+counts.Calibration;}
            }
            long trainBudget=(long)Math.Floor(training*epsilon+1e-9),calBudget=(long)Math.Floor(calibration*epsilon+1e-9);
            long trainAmbiguous=0,calAmbiguous=0,after=before;bool limited=false;
            var disabled=new HashSet<long>();
            foreach(long id in frequencies.Keys.Where(id=>!protectedIds.Contains(id)).OrderByDescending(id=>frequencies[id]).ThenBy(id=>id)) {
                token.ThrowIfCancellationRequested();
                if(timeRemaining!=null&&!timeRemaining()) {limited=true;break;}
                var affected=index[id].Select(word=>groups[word]).ToArray();
                var replacements=new Dictionary<TraceWord,Group>();
                long scratch=0;bool valid=true;
                try {
                    foreach(var group in affected) {
                        token.ThrowIfCancellationRequested();
                        if(timeRemaining!=null&&!timeRemaining()) {limited=true;valid=false;break;}
                        var word=new TraceWord(group.Word.Events.Where(value=>value!=id));
                        long bytes=256+word.Events.Length*16L;Charge(bytes);scratch+=bytes;
                        if(word.Events.Length==0) {valid=false;break;} // preserve activity for every nonempty baseline word
                        if(!replacements.TryGetValue(word,out var old))old=groups.GetValueOrDefault(word);
                        var next=new Group(old?.Word??word,group.Classes+(old?.Classes??0),
                            group.Training+(old?.Training??0),group.Calibration+(old?.Calibration??0));
                        if(next.Classes>maxCandidates) {valid=false;break;}
                        replacements[word]=next;
                    }
                    if(!valid) {if(limited)break;continue;}
                    long trainDelta=0,calDelta=0;
                    foreach(var group in affected.Where(group=>group.Classes>1)) {trainDelta-=group.Training;calDelta-=group.Calibration;}
                    foreach(var (word,next) in replacements) {
                        if(groups.TryGetValue(word,out var old)&&old.Classes>1) {trainDelta-=old.Training;calDelta-=old.Calibration;}
                        if(next.Classes>1) {trainDelta+=next.Training;calDelta+=next.Calibration;}
                    }
                    if(trainAmbiguous+trainDelta>trainBudget||calAmbiguous+calDelta>calBudget)continue;
                    // Deletion is committed only after every constraint passed.
                    foreach(var group in affected)Remove(group);
                    foreach(var (word,next) in replacements) {
                        if(groups.TryGetValue(word,out var old))Remove(old);
                        Add(next);
                    }
                    trainAmbiguous+=trainDelta;calAmbiguous+=calDelta;after-=frequencies[id];disabled.Add(id);
                } finally {Free(scratch);}
            }
            return new(disabled,trainAmbiguous,calAmbiguous,groups.Count==0?0:groups.Values.Max(group=>group.Classes),before,after,limited);
        } finally {if(owned!=0)release?.Invoke(owned);}
    }
}
