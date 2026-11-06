with open(r'C:\repo\AI_tracer_v2\code_analysis\DroidPos_8.2_MSD_review\DroidPos.9-12.20261013.trace', 'r', encoding='latin-1') as f:
    for idx, line in enumerate(f):
        if '761' in line:
            if any(k in line for k in ['Art', 'Item', 'art', 'item', 'ID', 'TransArticle', 'Appended', 'Replaying']):
                print(f'{idx+1}: {line.strip()[:140].encode("ascii", "replace").decode("ascii")}')
