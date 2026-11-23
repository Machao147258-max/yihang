# -*- coding: utf-8 -*-
import re, base64

so_path = r"C:\Users\dev\Desktop\样本\libs\libcoredex-x86.so"
with open(so_path, "rb") as f:
    data = f.read()

# 找 base64 候选串(>=12 字符,标准字符集,长度4的倍数附近)
cands = re.findall(rb"[A-Za-z0-9+/]{12,}={0,2}", data)
decoded = []
for c in cands:
    try:
        d = base64.b64decode(c + b"===")  # 补齐
    except Exception:
        continue
    # 只保留解码后是可打印 ASCII 的
    if all(0x20 <= b < 0x7f for b in d) and len(d) >= 3:
        decoded.append((c.decode(), d.decode(errors="replace")))

print("decoded candidates:", len(decoded))
keywords = ["frida", "magist", "kernel", "zygisk", "xposed", "lsp", "root", "su",
            "hook", "inject", "ptrace", "gum", "bp", "frida", "mumu", "qemu",
            "emulator", "substrate", "supersu", "magisk"]
for orig, d in decoded:
    low = d.lower()
    if any(k in low for k in keywords):
        print("  0x%x  %s  =>  %s" % (data.find(orig), orig, d))
print("\n--- 全部解码串(前 120 条) ---")
for orig, d in decoded[:120]:
    print("  %r => %r" % (orig, d))
