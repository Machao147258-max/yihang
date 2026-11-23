import frida, time, subprocess

ADB = r'"D:\Emu\nx_main\adb.exe" -s 127.0.0.1:7555'

jscode = """
var libbridge = Process.findModuleByName('libbridge.so');
var syms = libbridge.enumerateExports();
console.log('exports: ' + syms.length);
syms.forEach(function(s) {
    console.log(s.name + ' @ ' + s.address);
});
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
time.sleep(5)
session.detach()
