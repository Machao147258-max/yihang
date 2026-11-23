import frida, time, subprocess, sys

ADB = r'"D:\Emu\nx_main\adb.exe" -s 127.0.0.1:7555'
FRIDA_HOST = '127.0.0.1:8080'
PKG = 'com.target.app'
MAIN_ACT = '.modular.main.activity.EntryActivity'

jscode = '''
console.log('[HOOKS] loaded');

// 通过 enumerateExports 找 fopen
var libc = Process.findModuleByName('libc.so');
var fopenAddr = null;
var mmapAddr = null;
var lseekAddr = null;
var readAddr = null;

if (libc) {
    var syms = libc.enumerateExports();
    syms.forEach(function(s) {
        if (s.name === 'fopen') fopenAddr = s.address;
        else if (s.name === 'mmap') mmapAddr = s.address;
        else if (s.name === 'lseek') lseekAddr = s.address;
        else if (s.name === 'read') readAddr = s.address;
    });
    console.log('fopen=' + fopenAddr + ' mmap=' + mmapAddr + ' lseek=' + lseekAddr + ' read=' + readAddr);
}

function attachHook(addr, name, filter) {
    if (!addr) { console.log('SKIP ' + name); return; }
    try {
        Interceptor.attach(addr, filter);
        console.log('OK ' + name);
    } catch(e) { console.log('FAIL ' + name + ': ' + e); }
}

attachHook(fopenAddr, 'fopen', {
    onEnter: function(args) {
        try {
            var path = args[0].readCString() || '';
            if (path.indexOf('target') >= 0 || path.indexOf('shell') >= 0 ||
                path.indexOf('Kbcrypter') >= 0 || path.indexOf('Coredex') >= 0 ||
                path.indexOf('corejni') >= 0 || path.indexOf('.so') >= 0 ||
                path.indexOf('assets/') >= 0) {
                var m = '';
                try { m = args[1].readCString() || ''; } catch(e) {}
                console.log('[fopen] ' + path + ' [' + m + ']');
            }
        } catch(e) {}
    }
});

attachHook(mmapAddr, 'mmap', {
    onEnter: function(args) {
        var size = args[1].toInt32();
        if (size > 50000 && size < 20000000) {
            console.log('[mmap] sz=' + size + ' prot=' + args[2].toInt32().toString(16));
        }
    }
});

attachHook(lseekAddr, 'lseek', {
    onEnter: function(args) {
        var off = args[1].toInt32();
        if (off > 500000) { console.log('[lseek] off=' + off); }
    }
});

attachHook(readAddr, 'read', {
    onEnter: function(args) {
        var cnt = args[2].toInt32();
        if (cnt > 50000) { console.log('[read] cnt=' + cnt); }
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