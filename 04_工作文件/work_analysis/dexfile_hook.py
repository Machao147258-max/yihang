import frida, time, subprocess, sys

ADB = r'"D:\Emu\nx_main\adb.exe" -s 127.0.0.1:7555'
FRIDA_HOST = '127.0.0.1:8080'
PKG = 'com.target.app'
MAIN_ACT = '.modular.main.activity.EntryActivity'

jscode = '''
console.log('loading');

// hook libdexfile.so 的 dex 加载
var dexfile = Process.findModuleByName('libdexfile.so');
if (dexfile) {
    console.log('dexfile @ ' + dexfile.base);
    dexfile.enumerateExports().forEach(function(s) {
        if (s.name.indexOf('DexFile') >= 0 || s.name.indexOf('Open') >= 0 || s.name.indexOf('Load') >= 0) {
            console.log(s.name);
        }
    });
}

// 再看 libart 的 class linker
var art = Process.findModuleByName('libart.so');
if (art) {
    console.log('\\nart.so exports:');
    art.enumerateExports().forEach(function(s) {
        var n = s.name;
        if (n.indexOf('LoadClass') >= 0 || n.indexOf('DexFile') >= 0 || n.indexOf('OatFile') >= 0 || n.indexOf('OpenDex') >= 0) {
            console.log(n);
        }
    });
}

// 枚举当前已加载的 odex/oat
Process.enumerateModules().forEach(function(m) {
    if (m.name.indexOf('base.odex') >= 0 || m.name.indexOf('base.vdex') >= 0 || m.name.indexOf('.odex') >= 0) {
        console.log('\\n[odex] ' + m.name + ' @ ' + m.base + ' sz=' + m.size);
    }
});
'''

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)

dev = frida.get_device_manager().add_remote_device(FRIDA_HOST)

subprocess.run(f'{ADB} shell "su -c \'am start -n {PKG}/{MAIN_ACT}\'"', shell=True)
time.sleep(3)

res = subprocess.check_output(f'{ADB} shell "su -c pidof {PKG}"', shell=True).decode().strip()
pid = int(res.split()[0])
print(f'PID={pid}')

session = dev.attach(pid)
script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
time.sleep(5)
session.detach()
print('done')