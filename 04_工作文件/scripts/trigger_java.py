# -*- coding: utf-8 -*-
# 自动触发:force-stop -> 启动 -> 轮询 attach -> 采集 25s
import frida, subprocess, time, sys

ADB = r"D:\Emu\nx_main\adb.exe"
DEVICE_ADDR = "127.0.0.1:45681"
PKG = "com.target.app"
SCRIPT_PATH = r"C:\Users\dev\Desktop\样本\probe_java.js"
OUT_PATH = r"C:\Users\dev\Desktop\样本\probe_java_output.log"

def adb(*args):
    r = subprocess.run([ADB, "-s", "127.0.0.1:7555"] + list(args), capture_output=True, text=True, timeout=30)
    return r.stdout + r.stderr

print("[*] force-stop", flush=True)
adb("shell", "am", "force-stop", PKG)
time.sleep(1)
print("[*] launch", flush=True)
adb("shell", "monkey", "-p", PKG, "-c", "android.intent.category.LAUNCHER", "1")
time.sleep(0.6)

device = frida.get_device_manager().add_remote_device(DEVICE_ADDR)
pid = None
t0 = time.time()
while time.time() - t0 < 15:
    try:
        for p in device.enumerate_processes():
            if p.name == PKG:
                pid = p.pid
                break
        if pid:
            break
    except Exception:
        pass
    time.sleep(0.2)

if not pid:
    print("[!] app pid not found in 15s", flush=True)
    sys.exit(1)

print("[*] attaching pid=%d" % pid, flush=True)
session = device.attach(pid)
with open(SCRIPT_PATH, "r", encoding="utf-8") as f:
    src = f.read()
script = session.create_script(src)
fout = open(OUT_PATH, "a", encoding="utf-8", errors="replace")
def on_message(msg, data):
    line = str(msg)
    fout.write(line + "\n"); fout.flush()
    print(msg.get("type", "?"), msg.get("payload", "")[:300], flush=True)
script.on("message", on_message)
script.load()
print("[*] loaded, triggering EntryActivity...", flush=True)
adb("shell", "am", "start", "-n", "com.target.app/.modular.main.activity.EntryActivity")
time.sleep(5)
print("[*] collecting 20s...", flush=True)
time.sleep(20)
print("[*] done. log=" + OUT_PATH, flush=True)
fout.close()
