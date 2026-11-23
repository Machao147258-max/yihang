#!/usr/bin/env python3
"""hook mprotect 拦截壳写回解密后的 so 段"""
import frida, time

jscode = """
'use strict';

var mprotect = Module.findExportByName('libc.so', 'mprotect');
var libcorejni = Process.findModuleByName('libcorejni.so');
console.log('[+] mprotect @ 0x' + mprotect.toString(16));
console.log('[+] libcorejni base=0x' + libcorejni.base.toString(16));

var pageSize = 4096;
var dumped = {};

Interceptor.attach(mprotect, {
    onEnter: function(args) {
        var addr = args[0].toInt32();
        var size = args[1].toInt32();
        var prot = args[2].toInt32();
        // 只监视非 libcorejni 自身区域 + 改为 rwx/r-x 的
        if (prot != 5 && prot != 7) return; // 只关心 r-x (5) rwx (7)
        if (addr >= libcorejni.base.toInt32() && addr < libcorejni.base.toInt32() + libcorejni.size) return;
        if (size < 16384) return; // 太小不是 so 代码段
        
        var key = addr.toString(16);
        if (!dumped[key]) {
            dumped[key] = true;
            console.log('[!] mprotect ' + (prot==7?'rwx':'r-x') + ' @ 0x' + addr.toString(16) + ' size=0x' + size.toString(16));
            
            // 等写完后 dump
            var thiz = this;
            thiz.dumpAddr = addr;
            thiz.dumpSize = size;
        }
    },
    onLeave: function(retval) {
        if (this.dumpSize) {
            try {
                var buf = ptr(this.dumpAddr).readByteArray(this.dumpSize);
                var fn = '/data/local/tmp/dexdec_' + this.dumpAddr.toString(16) + '.bin';
                var f = new File(fn, 'wb'); f.write(buf); f.close();
                console.log('[OK] dumped mprotect region ' + this.dumpSize + ' bytes');
            } catch(e) {
                console.log('[!] dump failed: ' + e);
            }
        }
    }
});

console.log('[+] mprotect hook ready');
"""

def on_msg(msg, data):
    if msg['type'] == 'send': print(msg['payload'])

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
session = dev.attach(2001)
script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
time.sleep(30)
session.detach()