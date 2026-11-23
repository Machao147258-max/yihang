import frida, time, subprocess

ADB = r'"D:\Emu\nx_main\adb.exe" -s 127.0.0.1:7555'
PKG = 'com.target.app'
MAIN_ACT = '.modular.main.activity.EntryActivity'

jscode = """
var libbridge = Process.findModuleByName('libbridge.so');
if (!libbridge) { console.log('no houdini'); }
else {
    var NativeBridgeItf = Module.findExportByName('libbridge.so', 'NativeBridgeItf');
    if (!NativeBridgeItf) { console.log('no NB'); }
    else {
        console.log('NB=' + NativeBridgeItf);
        var loadLib = NativeBridgeItf.add(0x10).readPointer();
        var loadLibExt = NativeBridgeItf.add(0x70).readPointer();
        
        Interceptor.attach(loadLib, {
            onEnter: function(args) {
                try { console.log('[NB] ' + args[0].readCString()); } catch(e) {}
            }
        });
        
        Interceptor.attach(loadLibExt, {
            onEnter: function(args) {
                try { console.log('[NBext] ' + args[0].readCString()); } catch(e) {}
            }
        });
        console.log('hooks OK');
    }
}

// 同时 hook openat (x86 侧)
var libc = Process.findModuleByName('libc.so');
libc.enumerateExports().forEach(function(s) {
    if (s.name === 'openat') {
        Interceptor.attach(s.address, {
            onEnter: function(args) {
                try {
                    var path = args[1].readCString();
                    if (path.indexOf('target')>=0||path.indexOf('.so')>=0||path.indexOf('shell')>=0||path.indexOf('assets/')>=0) {
                        console.log('[openat] ' + path);
                    }
                } catch(e) {}
            }
        });
    }
});
"""

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')

# kill, start, fast poll
subprocess.run(ADB + ' shell "su -c \'am force-stop ' + PKG + '; sleep 1\'"', shell=True)
subprocess.run(ADB + ' shell "su -c \'am start -n ' + PKG + '/' + MAIN_ACT + '\' 2>/dev/null"', shell=True)

pid = None
for i in range(50):
    time.sleep(0.1)
    try:
        res = subprocess.check_output(ADB + ' shell "su -c pidof ' + PKG + '"', shell=True).decode().strip()
        if res:
            pid = int(res.split()[0])
            print('PID=' + str(pid) + ' @ ' + str((i+1)*0.1) + 's')
            break
    except: pass

if not pid:
    print('no PID')
else:
    try:
        session = dev.attach(pid)
        script = session.create_script(jscode)
        script.on('message', on_msg)
        script.load()
        print('capture 20s...')
        time.sleep(20)
        session.detach()
    except Exception as e:
        print('err: ' + str(e))

print('done')
