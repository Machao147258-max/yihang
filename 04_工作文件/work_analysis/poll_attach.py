import frida, time, subprocess, sys

ADB = r'"D:\Emu\nx_main\adb.exe" -s 127.0.0.1:7555'
FRIDA_HOST = '127.0.0.1:8080'
PKG = 'com.target.app'
MAIN_ACT = '.modular.main.activity.EntryActivity'

jscode = '''
console.log('[HOOKS] loaded at ' + Date.now());

// fopen - 只看 target 相关
var fopen = Module.findExportByName('libc.so', 'fopen');
if (fopen) {
    Interceptor.attach(fopen, {
        onEnter: function(args) {
            try {
                var path = args[0].readCString() || '';
                if (path.indexOf('target') >= 0 || path.indexOf('app') >= 0 ||
                    path.indexOf('shell') >= 0 || path.indexOf('Kbcrypter') >= 0 ||
                    path.indexOf('Coredex') >= 0 || path.indexOf('corejni') >= 0 ||
                    path.indexOf('.so') >= 0) {
                    var m = '';
                    try { m = args[1].readCString() || ''; } catch(e) {}
                    console.log('[fopen] ' + path + ' [' + m + ']');
                }
            } catch(e) {}
        }
    });
}

// mmap - 大块映射
var mmap = Module.findExportByName('libc.so', 'mmap');
if (mmap) {
    Interceptor.attach(mmap, {
        onEnter: function(args) {
            var size = args[1].toInt32();
            if (size > 50000 && size < 20000000) {
                console.log('[mmap] sz=' + size + ' prot=' + args[2].toInt32().toString(16));
            }
        }
    });
}

// lseek - 大偏移
var lseek = Module.findExportByName('libc.so', 'lseek');
if (lseek) {
    Interceptor.attach(lseek, {
        onEnter: function(args) {
            var off = args[1].toInt32();
            if (off > 500000) { console.log('[lseek] off=' + off); }
        }
    });
}

// read - 大块读取
var read = Module.findExportByName('libc.so', 'read');
if (read) {
    Interceptor.attach(read, {
        onEnter: function(args) {
            var cnt = args[2].toInt32();
            if (cnt > 50000) { console.log('[read] cnt=' + cnt); }
        }
    });
}

console.log('[HOOKS] all installed');
'''

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)
    if msg.get('type') == 'error':
        print('[ERR]', msg.get('description', '')[:100])

dev = frida.get_device_manager().add_remote_device(FRIDA_HOST)

# 启动 app
subprocess.run(f'{ADB} shell "su -c \'am start -n {PKG}/{MAIN_ACT}\'"', shell=True)

# 快速轮询 PID
pid = None
for _ in range(30):
    time.sleep(0.3)
    try:
        res = subprocess.check_output(f'{ADB} shell "su -c pidof {PKG}"', shell=True).decode().strip()
        if res:
            pid = int(res.split()[0])
            break
    except:
        continue

if not pid:
    print('[!] PID not found')
    sys.exit(1)

print(f'PID={pid} (found in {(_+1)*0.3:.1f}s)')

try:
    session = dev.attach(pid)
    script = session.create_script(jscode)
    script.on('message', on_msg)
    script.load()
    print('capturing 25s...')
    time.sleep(25)
    session.detach()
except Exception as e:
    print(f'[!] attach/run failed: {e}')

print('done')