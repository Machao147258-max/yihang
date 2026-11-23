import frida, time, subprocess

ADB = r'"D:\Emu\nx_main\adb.exe" -s 127.0.0.1:7555'

jscode = """
console.log('start');
var libbridge = Process.findModuleByName('libbridge.so');
console.log('libbridge @ ' + libbridge.base + ' sz=' + libbridge.size);

var NativeBridgeItf = Module.findExportByName('libbridge.so', 'NativeBridgeItf');
console.log('NativeBridgeItf @ ' + NativeBridgeItf);

var v = NativeBridgeItf.readInt();
console.log('version=' + v);
console.log('loadLibrary @ ' + NativeBridgeItf.add(0x10).readPointer());
console.log('getTrampoline @ ' + NativeBridgeItf.add(0x18).readPointer());
console.log('loadLibraryExt @ ' + NativeBridgeItf.add(0x70).readPointer());
console.log('done');
"""

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
res = subprocess.check_output(ADB + ' shell "su -c pidof com.target.app"', shell=True).decode().strip()
pid = int(res.split()[0])
print('PID=' + str(pid))

session = dev.attach(pid)
script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
time.sleep(3)
session.detach()
