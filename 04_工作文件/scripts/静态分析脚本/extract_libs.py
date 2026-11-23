# -*- coding: utf-8 -*-
import zipfile, os

apk = r"C:\Users\dev\Desktop\样本\base.apk"
outdir = r"C:\Users\dev\Desktop\样本\libs"
os.makedirs(outdir, exist_ok=True)
z = zipfile.ZipFile(apk)
hits = []
for name in z.namelist():
    if name.startswith("lib/") and (name.endswith(".so")):
        hits.append(name)
print("so entries:", len(hits))
for n in hits:
    if "Coredex" in n:
        print("TARGET:", n, z.getinfo(n).file_size)
        data = z.read(n)
        with open(os.path.join(outdir, os.path.basename(n)), "wb") as f:
            f.write(data)
        print("saved:", os.path.join(outdir, os.path.basename(n)))
