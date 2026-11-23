#!/usr/bin/env python3
"""frida 调 ART LoadLibrary 加载 KbcrypterCrypter"""
import frida, time, os

jscode = """
'use strict';

// 枚举 ART 加载相关
var art_mod = Process.findModuleByName('libart.so') || Process.findModuleByName('libartd.so');
if (!art_mod) {
    console.log('[!] libart not found, trying libnativebridge');
    art_mod = Process.findModuleByName('libnativebridge.so');
}
console.log('[!] libart base=0x' + art_mod.base.toString(16));

// 找 LoadLibrary 导出
var syms = art_mod.enumerateExports();
var found = [];
syms.forEach(function(s) {
    if (s.name.indexOf('LoadLibrary') >= 0 || s.name.indexOf('loadLibrary') >= 0) {
        found.push(s);
        console.log('[sym] ' + s.name);
    }
});

// 如果找到了，调它
if (found.length > 0) {
    var fn = new NativeFunction(found[0].address, 'void*', ['pointer', 'pointer', 'pointer']);
    console.log('[+] calling LoadLibrary...');
} else {
    console.log('[!] no LoadLibrary found, trying libandroid_runtime');
    var ar = Process.findModuleByName('libandroid_runtime.so');
    if (ar) {
        syms = ar.enumerateExports();
        syms.forEach(function(s) {
            if (s.name.indexOf('LoadLibrary') >= 0 || s.name.indexOf('nativeLoad') >= 0) {
                found.push(s);
                console.log('[sym] ' + s.name);
            }
        });
    }
    if (found.length === 0) {
        // 最后手段: 直接调 System.loadLibrary
        var linker = Module.findExportByName('linker64', '__loader_dlopen');
        var path = Memory.allocUtf8String('libKbCrypter.so');
        var ret = new NativeFunction(linker, 'pointer', ['pointer', 'int', 'pointer'])(path, 1, ptr(0));
        console.log('[!] dlopen result: ' + ret);
    }
}
"""

def on_msg(msg, data):
    if msg['type'] == 'send': print(msg['payload'])

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
session = dev.attach(2001)
script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
time.sleep(5)
session.detach()