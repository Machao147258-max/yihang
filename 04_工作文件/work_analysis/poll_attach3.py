import frida, time, subprocess, sys

ADB = r'"D:\Emu\nx_main\adb.exe" -s 127.0.0.1:7555'
FRIDA_HOST = '127.0.0.1:8080'
PKG = 'com.target.app'
MAIN_ACT = '.modular.main.activity.EntryActivity'

jscode = '''
console.log('[HOOKS] loaded');

var libc = Process.findModuleByName('libc.so');
var addrs = {};

if (libc) {
    libc.enumerateExports().forEach(function(s) {
        if (['open','openat','fopen','fopen64','open64','read','lseek','mmap','dlopen','__loader_dlopen'].indexOf(s.name) >= 0) {
            addrs[s.name] = s.address;
            console.log(s.name + '=' + s.address);
        }
    });
}

function hook(addr, name, enterFn) {
    if (!addr) { console.log('SKIP ' + name); return; }
    try { Interceptor.attach(addr, { onEnter: enterFn }); console.log('OK ' + name); }
    catch(e) { console.log('FAIL ' + name + ': ' + e); }
}

// open/openat - 捕获文件打开（不带 fopen 的壳会用这个）
hook(addrs['open'], 'open', {
    onEnter: function(args) {
        try {
            var path = args[0].readCString() || '';
            if (path.indexOf('target') >= 0 || path.indexOf('shell') >= 0 ||
                path.indexOf('Kbcrypter') >= 0 || path.indexOf('Coredex') >= 0 ||
                path.indexOf('corejni') >= 0 || path.indexOf('.so') >= 0 ||
                path.indexOf('assets/') >= 0 || path.indexOf('.dex') >= 0) {
                console.log('[open] ' + path + ' flags=' + args[1]);
            }
        } catch(e) {}
    }
});

hook(addrs['openat'], 'openat', {
    onEnter: function(args) {
        try {
            var path = args[1].readCString() || '';
            if (path.indexOf('target') >= 0 || path.indexOf('shell') >= 0 ||
                path.indexOf('Kbcrypter') >= 0 || path.indexOf('Coredex') >= 0 ||
                path.indexOf('corejni') >= 0 || path.indexOf('.so') >= 0 ||
                path.indexOf('assets/') >= 0 || path.indexOf('.dex') >= 0) {
                console.log('[openat] ' + path + ' flags=' + args[2]);
            }
        } catch(e) {}
    }
});

hook(addrs['fopen'], 'fopen', {
    onEnter: function(args) {
        try {
            var path = args[0].readCString() || '';
            if (path.indexOf('target') >= 0 || path.indexOf('shell') >= 0 ||
                path.indexOf('Kbcrypter') >= 0 || path.indexOf('Coredex') >= 0 ||
                path.indexOf('corejni') >= 0 || path.indexOf('.so') >= 0) {
                console.log('[fopen] ' + path);
            }
        } catch(e) {}
    }
});

hook(addrs['mmap'], 'mmap', {
    onEnter: function(args) {
        var size = args[1].toInt32();
        if (size > 100000 && size < 20000000) {
            console.log('[mmap] sz=' + size + ' prot=' + args[2].toInt32().toString(16));
        }
    }
});

hook(addrs['dlopen'], 'dlopen', {
    onEnter: function(args) {
        try {
            var path = args[0].readCString() || '';
            if (path.indexOf('Kbcrypter') >= 0 || path.indexOf('shell') >= 0) {
                console.log('[dlopen] ' + path);
            }
        } catch(e) {}
    }
});

console.log('[HOOKS] all done');
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
            print(f'PID={pid} at {(i+1)*0.3:.1f}s')
            break
    except: pass

if not pid: print('[!] no PID'); sys.exit(1)

try:
    session = dev.attach(pid)
    script = session.create_script(jscode)
    script.on('message', on_msg)
    script.load()
    print('capturing 30s...')
    time.sleep(30)
    session.detach()
except Exception as e:
    print(f'[!] {e}')

print('done')