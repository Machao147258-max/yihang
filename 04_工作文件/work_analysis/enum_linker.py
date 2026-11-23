#!/usr/bin/env python3
"""枚举 linker64 的 dlopen 相关导出"""
import frida, time

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')

jscode = """
'use strict';
var mod = Process.findModuleByName('linker64');
var syms = mod.enumerateExports();
console.log('[+] linker64 exports: ' + syms.length);
var n = 0;
syms.forEach(function(s) {
    if (s.name.indexOf('dlopen') >= 0 || s.name.indexOf('dlopen') >= 0) {
        console.log('  ' + s.name + ' @ 0x' + s.address.toString(16));
        n++;
    }
});
if (n === 0) {
    // fallback: 枚举所有
    syms.forEach(function(s) {
        if (s.name.indexOf('dl') >= 0 || s.name.indexOf('DO') >= 0) {
            console.log('  ' + s.name + ' @ 0x' + s.address.toString(16));
        }
    });
}
"""

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
session = dev.attach(2001)
script = session.create_script(jscode)
script.on('message', lambda m,d: print(m.get('payload','')))
script.load()
time.sleep(3)
session.detach()