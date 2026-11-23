import frida, time, subprocess

ADB = r'"D:\Emu\nx_main\adb.exe" -s 127.0.0.1:7555'
FRIDA_HOST = '127.0.0.1:8080'
PKG = 'com.target.app'
MAIN_ACT = '.modular.main.activity.EntryActivity'

jscode = """
console.log('loading NativeBridge hook...');

var libbridge = Process.findModuleByName('libbridge.so');
if (!libbridge) {
    console.log('libbridge not found');
}

var NativeBridgeItf = Module.findExportByName('libbridge.so', 'NativeBridgeItf');
if (!NativeBridgeItf) {
    console.log('NativeBridgeItf not found');
} else {
    console.log('NativeBridgeItf @ ' + NativeBridgeItf);
    
    var loadLibrary = NativeBridgeItf.add(0x10).readPointer();
    var loadLibraryExt = NativeBridgeItf.add(0x70).readPointer();
    console.log('loadLibrary @ ' + loadLibrary);
    console.log('loadLibraryExt @ ' + loadLibraryExt);
    
    // hook loadLibrary
    if (!loadLibrary.isNull()) {
        Interceptor.attach(loadLibrary, {
            onEnter: function(args) {
                try {
                    var path = args[0].readCString();
                    console.log('[NB.loadLib] ' + path + ' flags=' + args[1].toInt32());
                } catch(e) {}
            },
            onLeave: function(retval) {
                console.log('[NB.loadLib] ret=' + retval);
            }
        });
        console.log('hook loadLibrary OK');
    }
    
    // hook loadLibraryExt  
    if (!loadLibraryExt.isNull()) {
        Interceptor.attach(loadLibraryExt, {
            onEnter: function(args) {
                try {
                    var path = args[0].readCString();
                    console.log('[NB.loadLibExt] ' + path + ' flags=' + args[1].toInt32());
                } catch(e) {}
            },
            onLeave: function(retval) {
                console.log('[NB.loadLibExt] ret=' + retval);
            }
        });
        console.log('hook loadLibraryExt OK');
    }
}
"""

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)

dev = frida.get_device_manager().add_remote_device(FRIDA_HOST)

# kill and restart app
subprocess.run(ADB + ' shell "su -c \'am force-stop ' + PKG + '; sleep 1\'"', shell=True)
subprocess.run(ADB + ' shell "su -c \'am start -n ' + PKG + '/' + MAIN_ACT + '\' 2>/dev/null"', shell=True)

# wait for PID
pid = None
for i in range(30):
    time.sleep(0.3)
    try:
        res = subprocess.check_output(ADB + ' shell "su -c pidof ' + PKG + '"', shell=True).decode().strip()
        if res:
            pid = int(res.split()[0])
            print('PID=' + str(pid) + ' @ ' + str((i+1)*0.3) + 's')
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
        print('capturing 30s...')
        time.sleep(30)
        session.detach()
    except Exception as e:
        print('err: ' + str(e))

print('done')