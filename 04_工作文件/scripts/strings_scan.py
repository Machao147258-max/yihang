# -*- coding: utf-8 -*-
import re, sys

so_path = r"C:\Users\dev\Desktop\样本\libs\libcoredex-x86.so"
with open(so_path, "rb") as f:
    data = f.read()
print("so size:", len(data))

# 提取 ASCII 字符串(>=4 字符)
strs = [(m.start(), m.group().decode("ascii", "replace")) for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]
print("strings:", len(strs))

keywords = ["frida", "magisk", "kernelsu", "supersu", "superuser", "su", "busybox",
            "xposed", "lsposed", "lspd", "zygisk", "riru", "shamiko", "ptrace",
            "/proc/self/maps", "/proc/", "/proc/self/", "emulator", "qemu", "genymotion",
            "mumu", "ro.kernel", "debug", "gum", "hook", "inject", "substrate",
            "root", "su_", "/system/bin", "/sbin", "test-keys", "devtool", "tq", "meet"]

for kw in keywords:
    found = []
    for off, s in strs:
        if kw in s.lower():
            found.append((off, s))
    if found:
        print("\n## '%s' (%d hits)" % (kw, len(found)))
        for off, s in found[:12]:
            print("  0x%x  %r" % (off, s[:80]))
