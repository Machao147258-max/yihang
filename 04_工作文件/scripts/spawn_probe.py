# -*- coding: utf-8 -*-
# 药都农商样本 spawn 探测:spawn + attach + resume 一条龙,frida 输出写文件
import frida, sys, time

DEVICE = "127.0.0.1:27042"
PKG = "com.target.app"
SCRIPT_PATH = r"C:\Users\dev\Desktop\样本\bypass_maps.js"
OUT_PATH = r"C:\Users\dev\Desktop\样本\probe_output.log"
RUN_SECONDS = 300

device = frida.get_device_manager().add_remote_device(DEVICE)
print("[*] spawning " + PKG)
pid = device.spawn([PKG])
print("[*] spawned pid=%d" % pid)
session = device.attach(pid)
with open(SCRIPT_PATH, "r", encoding="utf-8") as f:
    src = f.read()
script = session.create_script(src)

fout = open(OUT_PATH, "a", encoding="utf-8", errors="replace")
def on_message(msg, data):
    line = str(msg)
    fout.write(line + "\n")
    fout.flush()
    print(msg.get("type", "?"), str(msg.get("payload", ""))[:200])
script.on("message", on_message)
script.load()
print("[*] hooks loaded, resuming...")
device.resume(pid)
time.sleep(RUN_SECONDS)
print("[*] done, output at " + OUT_PATH)
fout.close()
