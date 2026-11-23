import frida, time, subprocess

ADB = '"D:\\Emu\\nx_main\\adb.exe" -s 127.0.0.1:7555'
PKG = 'com.target.app'
MAIN = '.modular.main.activity.EntryActivity'

jscode = """
function hookAll() {
    ['libdexfile.so', 'libart.so', 'libdexfile.so'].forEach(function(modname) {
        var mod = Process.findModuleByName(modname);
        if (!mod) return;
        mod.enumerateExports().forEach(function(s) {
            if (s.name.indexOf('OpenMemory') >= 0 || s.name.indexOf('OpenCommon') >= 0) {
                try {
                    Interceptor.attach(s.address, {
                        onEnter: function(args) {
                            var base = args[0];
                            var size = args[1].toInt32();
                            send('CALL ' + s.name + ' base=' + base + ' size=' + size);
                            if (size > 1000 && size < 60000000 && !base.isNull()) {
                                try {
                                    var magic = base.readByteArray(8);
                                    var a = new Uint8Array(magic);
                                    send('  magic: ' + Array.from(a).map(function(b){return b.toString(16)}).join(' '));
                                    if (a[0]===0x64 && a[1]===0x65 && a[2]===0x78) {
                                        var buf = base.readByteArray(size);
                                        var fn = '/data/local/tmp/openmem_' + size + '.dex';
                                        var f = new File(fn, 'wb'); f.write(buf); f.close();
                                        send('  SAVED ' + fn);
                                    }
                                } catch(e) { send('  read err: ' + e); }
                            }
                        }
                    });
                    send('HOOKED ' + s.name);
                } catch(e) {}
            }
        });
    });
    send('all hooks installed');
}
hookAll();
"""

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')

subprocess.run(ADB + ' shell "su -c \'am force-stop ' + PKG + '; sleep 1\'"', shell=True)
subprocess.run(ADB + ' shell "su -c \'am start -n ' + PKG + '/' + MAIN + '\' 2>/dev/null"', shell=True)

pid = None
for i in range(60):
    time.sleep(0.1)
    try:
        res = subprocess.check_output(ADB + ' shell "su -c pidof ' + PKG + '"', shell=True).decode().strip()
        if res:
            pid = int(res.split()[0])
            print('PID=' + str(pid) + ' @ ' + str((i+1)*0.1) + 's')
            break
    except: pass

if pid:
    session = None
    time.sleep(1.0)
    for attempt in range(8):
        try:
            session = dev.attach(pid)
            print('attached on attempt ' + str(attempt+1))
            break
        except Exception as e:
            print('attach attempt ' + str(attempt+1) + ' failed: ' + str(e)[:60])
            time.sleep(0.5)
    if session:
        try:
            script = session.create_script(jscode)
            script.on('message', on_msg)
            script.load()
            print('hooks loaded, capturing 20s...')
            time.sleep(20)
            session.detach()
        except Exception as e:
            print('script failed: ' + str(e)[:100])
print('done')
