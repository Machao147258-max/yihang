#!/usr/bin/env python3
"""frida 强制加载 libKbCrypter.so 并 dump"""
import frida, time, os

DEV = '127.0.0.1:8080'

jscode = """
'use strict';

// 直接调 linker 的 dlopen
var dlopen = Module.findExportByName('linker64', '__loader_dlopen');
console.log('[+] dlopen @ 0x' + dlopen.toString(16));

// 找到 libcorejni.so
var mod = Process.findModuleByName('libcorejni.so');
console.log('[+] libcorejni @ 0x' + mod.base.toString(16));

// 构造路径
var path = Memory.allocUtf8String('/data/app/~~4_ZFMg_loVUm4BjhyOh_9w==/com.target.app-xxxxxxxxxxxxxxxxxxxx==/lib/arm64/libKbCrypter.so');

// 手动 dlopen
console.log('[!] calling dlopen...');
var ret = new NativeFunction(dlopen, 'pointer', ['pointer', 'pointer', 'pointer'])(path, ptr(0), ptr(0));
console.log('[+] dlopen returned: 0x' + ret.toString(16));

if (ret.toInt32() !== 0) {
    // 等一帧让初始化完成
    setTimeout(function() {
        var skb = Process.findModuleByName('libKbCrypter.so');
        if (skb) {
            console.log('[!] KbcrypterCrypter found @ 0x' + skb.base.toString(16) + ' size=0x' + skb.size.toString(16));
            
            // dump 全部段
            ['r-x', 'r--', 'rw-'].forEach(function(perm) {
                var ranges = skb.enumerateRanges(perm);
                ranges.forEach(function(r) {
                    var buf = r.base.readByteArray(r.size);
                    var fname = '/data/local/tmp/skb_' + r.base.toString(16) + '.bin';
                    var f = new File(fname, 'wb'); f.write(buf); f.close();
                    console.log('[OK] ' + perm + ' @0x' + r.base.toString(16) + ' size=' + r.size + ' -> ' + fname);
                });
            });
        }
    }, 500);
} else {
    console.log('[!] dlopen failed');
}
"""

def on_msg(msg, data):
    if msg['type'] == 'send':
        print(msg['payload'])
    elif msg['type'] == 'error':
        print('[ERR]', msg['description'])

dev = frida.get_device_manager().add_remote_device(DEV)
session = dev.attach(2001)
print('[+] attached')

script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
print('[+] loaded')

time.sleep(10)
session.detach()
print('[+] done')