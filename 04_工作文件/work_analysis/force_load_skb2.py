#!/usr/bin/env python3
"""frida Module.load 直接加载 KbcrypterCrypter"""
import frida, time

DEV = '127.0.0.1:8080'

jscode = """
'use strict';

var path = '/data/app/~~4_ZFMg_loVUm4BjhyOh_9w==/com.target.app-xxxxxxxxxxxxxxxxxxxx==/lib/arm64/libKbCrypter.so';

console.log('[!] Module.load ' + path);
try {
    var mod = Module.load(path);
    console.log('[+] loaded: ' + mod.name + ' base=0x' + mod.base.toString(16) + ' size=0x' + mod.size.toString(16));
    
    // dump 所有段
    ['r-x', 'r--', 'rw-'].forEach(function(perm) {
        var ranges = mod.enumerateRanges(perm);
        ranges.forEach(function(r) {
            var buf = r.base.readByteArray(r.size);
            var fname = '/data/local/tmp/skb_' + r.base.toString(16) + '.bin';
            var f = new File(fname, 'wb'); f.write(buf); f.close();
            console.log('[OK] ' + perm + ' @0x' + r.base.toString(16) + ' -> ' + fname);
        });
    });
} catch(e) {
    console.log('[!] Module.load failed: ' + e);
    // fallback: 用 libdl.so 的 dlopen
    var dlfunc = Module.findExportByName('libdl.so', 'dlopen');
    if (dlfunc) {
        console.log('[+] libdl.dlopen @ 0x' + dlfunc.toString(16));
        var p = Memory.allocUtf8String(path);
        var dlopen = new NativeFunction(dlfunc, 'pointer', ['pointer', 'int32']);
        var ret = dlopen(p, 1); // RTLD_NOW = 1
        console.log('[+] dlopen ret=0x' + ret.toString(16));
        if (ret.toInt32() !== 0) {
            mod = Process.findModuleByName('libKbCrypter.so');
            console.log('[+] found module: ' + (mod ? 'yes' : 'no'));
        }
    }
}
"""

def on_msg(msg, data):
    if msg['type'] == 'send': print(msg['payload'])
    elif msg['type'] == 'error': print('[ERR]', msg.get('description',''))

dev = frida.get_device_manager().add_remote_device(DEV)
session = dev.attach(2001)
script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
time.sleep(10)
session.detach()