import frida, time, subprocess

ADB = '"D:\\Emu\\nx_main\\adb.exe" -s 127.0.0.1:7555'
dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')

res = subprocess.check_output(f'{ADB} shell "su -c pidof com.target.app"', shell=True).decode().strip()
PID = int(res.split()[0])
print(f'PID={PID}')

session = dev.attach(PID)
script = session.create_script('''
var nb = Module.findExportByName("libbridge.so", "NativeBridgeItf");
send("NB=" + nb);
send("v=" + nb.readInt());
send("loadLib=" + nb.add(0x10).readPointer());
send("loadLibExt=" + nb.add(0x70).readPointer());
''')
script.on('message', lambda m,d: print(m.get('payload','') or m))
script.load()
time.sleep(3)
session.detach()
print('done')
