# -*- coding: utf-8 -*-
import zipfile
apk = r"C:\Users\dev\Desktop\样本\base.apk"
z = zipfile.ZipFile(apk)
dirs = {}
for name in z.namelist():
    if name.startswith("lib/") and name.count("/") >= 2:
        arch = name.split("/")[1]
        dirs.setdefault(arch, []).append(name.split("/")[-1])
for arch, files in dirs.items():
    print(arch, len(files))
    if any("Coredex" in f for f in files):
        for f in files:
            if "Coredex" in f:
                print("   ", f, z.getinfo("lib/" + arch + "/" + f).file_size)
