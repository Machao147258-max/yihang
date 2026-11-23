#!/usr/bin/env python3
"""frida 调解读引擎 0x1184 解密 KbcrypterCrypter"""
import frida, time

jscode = """
'use strict';

var libcorejni = Process.findModuleByName('libcorejni.so');
if (!libcorejni) { console.log('[!] libcorejni not found'); }
console.log('[+] libcorejni base=0x' + libcorejni.base.toString(16));

// 解密函数地址 (0x1184 from file offset = same as vaddr)
var decFunc = libcorejni.base.add(0x1184);
console.log('[+] decFunc @ 0x' + decFunc.toString(16));

// 构造参数：加密 so 的文件路径
var soPath = '/data/app/~~4_ZFMg_loVUm4BjhyOh_9w==/com.target.app-xxxxxxxxxxxxxxxxxxxx==/lib/arm64/libKbCrypter.so';
var pPath = Memory.allocUtf8String(soPath);
console.log('[+] path @ ' + pPath);

// 调解密函数
try {
    var fn = new NativeFunction(decFunc, 'int', ['pointer']);
    console.log('[!] calling decFunc...');
    var ret = fn(pPath);
    console.log('[+] decFunc returned: ' + ret);
    
    // 等一帧让解密完成
    setTimeout(function() {
        var skb = Process.findModuleByName('libKbCrypter.so');
        if (skb) {
            console.log('[+] KbcrypterCrypter found @ 0x' + skb.base.toString(16));
            ['r-x','r--','rw-'].forEach(function(perm) {
                var ranges = skb.enumerateRanges(perm);
                ranges.forEach(function(r) {
                    var buf = r.base.readByteArray(r.size);
                    var fn = '/data/local/tmp/skb_' + perm.replace('-','') + '_' + r.base.toString(16) + '.bin';
                    var f = new File(fn, 'wb'); f.write(buf); f.close();
                    console.log('[OK] ' + perm + ' -> ' + fn);
                });
            });
        } else {
            console.log('[!] not loaded after call');
        }
    }, 2000);
} catch(e) {
    console.log('[!] NativeFunction failed: ' + e);
    // 尝试用 Interceptor.replace 先占位再看
}
"""

def on_msg(msg, data):
    if msg['type'] == 'send': print(msg['payload'])

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
session = dev.attach(2001)
script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
time.sleep(8)
session.detach()