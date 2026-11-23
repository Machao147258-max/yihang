import frida, time, subprocess

ADB = r'"D:\Emu\nx_main\adb.exe" -s 127.0.0.1:7555'

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')

jscode = '''
console.log('[+] hooks loading');

Interceptor.attach(Module.findExportByName('libc.so', 'fopen'), {
    onEnter: function(args) {
        try {
            var path = args[0].readCString() || '';
            if (path.indexOf('.so') >= 0 || path.indexOf('/data/app/') >= 0 || 
                path.indexOf('shell') >= 0 || path.indexOf('assets/') >= 0) {
                var mode = '';
                try { mode = args[1].readCString() || ''; } catch(e) {}
                console.log('[fopen] ' + path + ' [' + mode + ']');
            }
        } catch(e) {}
    }
});

var mmap = Module.findExportByName('libc.so', 'mmap');
if (mmap) {
    Interceptor.attach(mmap, {
        onEnter: function(args) {
            var size = args[1].toInt32();
            if (size > 50000 && size < 20000000) {
                console.log('[mmap] size=' + size + ' prot=' + args[2].toInt32());
            }
        }
    });
}

var lseek = Module.findExportByName('libc.so', 'lseek');
if (lseek) {
    Interceptor.attach(lseek, {
        onEnter: function(args) {
            var off = args[1].toInt32();
            if (off > 100000) { console.log('[lseek] offset=' + off); }
        }
    });
}

console.log('[+] hooks ready');
'''

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)

# Start app
subprocess.run(ADB + ' shell "su -c \'am start -n com.target.app/.modular.main.activity.EntryActivity\'"', shell=True)
time.sleep(3)

# Get PID
res = subprocess.check_output(ADB + ' shell "su -c pidof com.target.app"', shell=True).decode().strip()
pid = int(res.split()[0])
print(f'PID={pid}')

session = dev.attach(pid)
script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
print('capturing...')
time.sleep(20)
session.detach()
print('done')