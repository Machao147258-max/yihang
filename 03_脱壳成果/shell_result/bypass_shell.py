import frida, time, subprocess

ADB = '"D:\\Emu\\nx_main\\adb.exe" -s 127.0.0.1:7555'
PKG = 'com.target.app'
MAIN = '.modular.main.activity.EntryActivity'

# 先把 nosuke 重启（之前可能被之前的 hook 搞坏了）
subprocess.run(f'{ADB} shell "su -c \'kill $(pidof frida-server) 2>/dev/null; sleep 1; nohup /data/local/tmp/frida-server -l 0.0.0.0:8080 &>/dev/null &\'"', shell=True)
time.sleep(3)

jscode = """
console.log('[1] find NativeBridgeItf...');
var mod = Process.findModuleByName('libbridge.so');
var found = null;
mod.enumerateExports().forEach(function(s) {
    if (s.name === 'NativeBridgeItf') found = s.address;
});

var nb = found;
console.log('NB=' + nb + ' v=' + nb.readInt());
var loadLibExt = nb.add(0x70).readPointer();
console.log('loadLibExt=' + loadLibExt);

// 记录所有加载的 SO
var loadedSOs = [];

Interceptor.attach(loadLibExt, {
    onEnter: function(args) {
        try {
            var path = args[0].readCString();
            loadedSOs.push(path);
            console.log('[NB] ' + path);
        } catch(e) {}
    }
});
console.log('[2] loadLibExt hook OK');

// 同时 hook __system_property_get 检测反调试
var propGet = Module.findExportByName('libc.so', '__system_property_get');
if (propGet) {
    Interceptor.attach(propGet, {
        onEnter: function(args) {
            try {
                var name = args[0].readCString();
                if (name.indexOf('tracerpid') >= 0 || name.indexOf('TracerPid') >= 0) {
                    console.log('[PROP] tracerpid query! patching to 0');
                    // 写 0 到返回值 buffer
                    args[1].writeUtf8String('0');
                }
            } catch(e) {}
        }
    });
    console.log('[3] __system_property_get hook OK');
}

// hook pthread_create 抓反调试线程
var pthreadCreate = Module.findExportByName('libc.so', 'pthread_create');
if (pthreadCreate) {
    Interceptor.attach(pthreadCreate, {
        onEnter: function(args) {
            var funcPtr = args[2];
            // 判断是否在 libcoredex-x86.so 范围内
            var helper = Process.findModuleByName('libcoredex-x86.so');
            if (helper) {
                if (funcPtr.compare(helper.base) >= 0 && funcPtr.compare(helper.base.add(helper.size)) < 0) {
                    console.log('[PTHREAD] from Coredex! offset=' + funcPtr.sub(helper.base));
                }
            }
        }
    });
    console.log('[4] pthread_create hook OK');
}

console.log('[5] all hooks ready, waiting...');
"""

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
subprocess.run(f'{ADB} shell "su -c \'am force-stop {PKG}; sleep 1\'"', shell=True)
subprocess.run(f'{ADB} shell "su -c \'am start -n {PKG}/{MAIN}\' 2>/dev/null"', shell=True)

pid = None
for i in range(50):
    time.sleep(0.1)
    try:
        res = subprocess.check_output(f'{ADB} shell "su -c pidof {PKG}"', shell=True).decode().strip()
        if res:
            pid = int(res.split()[0])
            print(f'PID={pid} @ {(i+1)*0.1}s')
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
        print('capture 25s...')
        time.sleep(25)
        session.detach()
    except Exception as e:
        print(f'err: {e}')

print('done')