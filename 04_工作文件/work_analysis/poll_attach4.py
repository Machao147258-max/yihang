import frida, time, subprocess, sys

ADB = r'"D:\Emu\nx_main\adb.exe" -s 127.0.0.1:7555'
FRIDA_HOST = '127.0.0.1:8080'
PKG = 'com.target.app'
MAIN_ACT = '.modular.main.activity.EntryActivity'

jscode = '''
console.log('loading hooks');

var libc = Process.findModuleByName('libc.so');
var syms = libc.enumerateExports();
var openat, fopen, mmap, dlopen;

syms.forEach(function(s) {
    if (s.name === 'openat' && !openat) openat = s.address;
    if (s.name === 'fopen' && !fopen) fopen = s.address;
    if (s.name === 'mmap' && !mmap) { mmap = s.address; console.log('mmap=' + mmap); }
    if (s.name === 'dlopen' && !dlopen) { dlopen = s.address; console.log('dlopen=' + dlopen); }
});

try {
    Interceptor.attach(openat, {
        onEnter: function(args) {
            try {
                var p = args[1].readCString() || '';
                if (p.indexOf('target')>=0||p.indexOf('shell')>=0||p.indexOf('Kbcrypter')>=0||p.indexOf('.so')>=0||p.indexOf('assets/')>=0) {
                    console.log('[openat] ' + p);
                }
            } catch(e) {}
        }
    });
    console.log('OK openat');
} catch(e) { console.log('FAIL openat: ' + e); }

try {
    Interceptor.attach(fopen, {
        onEnter: function(args) {
            try {
                var p = args[0].readCString() || '';
                if (p.indexOf('target')>=0||p.indexOf('shell')>=0||p.indexOf('.so')>=0||p.indexOf('assets/')>=0||p.indexOf('Kbcrypter')>=0) {
                    console.log('[fopen] ' + p);
                }
            } catch(e) {}
        }
    });
    console.log('OK fopen');
} catch(e) { console.log('FAIL fopen: ' + e); }

try {
    Interceptor.attach(mmap, {
        onEnter: function(args) {
            var sz = args[1].toInt32();
            if (sz > 100000 && sz < 20000000) console.log('[mmap] sz=' + sz);
        }
    });
    console.log('OK mmap');
} catch(e) { console.log('FAIL mmap: ' + e); }

try {
    Interceptor.attach(dlopen, {
        onEnter: function(args) {
            try {
                var p = args[0].readCString() || '';
                if (p.indexOf('shell')>=0||p.indexOf('Kbcrypter')>=0) console.log('[dlopen] ' + p);
            } catch(e) {}
        }
    });
    console.log('OK dlopen');
} catch(e) { console.log('FAIL dlopen: ' + e); }
'''

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)

dev = frida.get_device_manager().add_remote_device(FRIDA_HOST)

subprocess.run(f'{ADB} shell "su -c \'am force-stop {PKG}; sleep 1\'"', shell=True)
subprocess.run(f'{ADB} shell "su -c \'am start -n {PKG}/{MAIN_ACT}\'"', shell=True)

pid = None
for i in range(30):
    time.sleep(0.3)
    try:
        res = subprocess.check_output(f'{ADB} shell "su -c pidof {PKG}"', shell=True).decode().strip()
        if res:
            pid = int(res.split()[0])
            print(f'PID={pid} @ {(i+1)*0.3:.1f}s')
            break
    except: pass

if not pid: print('no PID'); sys.exit(1)

try:
    session = dev.attach(pid)
    script = session.create_script(jscode)
    script.on('message', on_msg)
    script.load()
    print('capture 30s...')
    time.sleep(30)
    session.detach()
except Exception as e:
    print(f'err: {e}')

print('done')