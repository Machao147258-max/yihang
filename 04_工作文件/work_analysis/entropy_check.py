import collections, math

BASE = 'C:/Users/dev/Desktop/样本/libs_arm64/'
for fn in ['libcorejni.so', 'libcoredex.so', 'libsecenv.so', 'libtinymagic.so']:
    d = open(BASE + fn, 'rb').read()
    CH = max(len(d) // 24, 4096)
    ents = []
    for off in range(0, len(d), CH):
        blk = d[off:off + CH]
        if len(blk) < 1024:
            continue
        c = collections.Counter(blk)
        ent = -sum((v / len(blk)) * math.log2(v / len(blk)) for v in c.values())
        ents.append(ent)
    cipher = sum(1 for e in ents if e > 7.2)
    print(f'{fn:22s} size={len(d)//1024:5d}KB blocks={len(ents)} cipher_blocks={cipher} avg={sum(ents)/len(ents):.2f}')
