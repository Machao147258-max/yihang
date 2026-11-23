#!/usr/bin/env python3
"""冷启动 app + hook 所有 dlopen 变体抓 KbcrypterCrypter"""
import frida, time, os

jscode = """
'use strict';

// hook 所有可能的加载点
var targets = [
    ['linker64', '__loader_dlopen'],
    ['linker64', '__loader_android_dlopen_ext'],
    ['libdl.so', 'dlopen'],
    ['libnativebridge.so', null],  // 全部导出
    ['libbridge.so', null],
];

targets.forEach(function(t) {
    var mod = Process.findModuleByName(t[0]);
    if (!mod) return;
    if (t[1]) {
        var addr = Module.findExportByName(t[0], t[1]);
        if (!addr) return;
        console.log('[hook] ' + t[0] + '.' + t[1]);
        Interceptor.attach(addr, {
            onEnter: function(args) {
                var s = args[0].readCString ? args[0].readCString() : '';
                if (s && (s.indexOf('Safe')>=0 || s.indexOf('safe')>=0 || s.indexOf('shell')>=0)) {
                    console.log('[!] LOADING ' + s);
                    this.doDump = true;
                }
            },
            onLeave: function(ret) {
                if (this.doDump && ret.toInt32() !== 0) {
                    console.log('[+] load OK, dumping');
                    try { dumpMod('libKbCrypter'); } catch(e) { console.log('  err: ' + e); }
                }
            }
        });
    } else {
        // hook 全部导出
        var syms = mod.enumerateExports();
        syms.forEach(function(s) {
            if (s.name.indexOf('Load') >= 0 || s.name.indexOf('load') >= 0 || s.name.indexOf('dlopen') >= 0) {
                var a = s.address;
                Interceptor.attach(a, {
                    onEnter: function(args) {
                        var name = '';
                        try { name = args[0].readCString() || ''; } catch(e) {}
                        if (name.indexOf('Safe')>=0 || name.indexOf('safe')>=0 || name.indexOf('shell')>=0) {
                            console.log('[!] BRIDGE load ' + name + ' via ' + s.name);
                            this.doDump = true;
                        }
                    },
                    onLeave: function(ret) {
                        if (this.doDump && ret.toInt32() !== 0) {
                            console.log('[+] bridge load OK');
                            try { dumpMod('libKbCrypter'); } catch(e) { console.log('  err: ' + e); }
                        }
                    }
                });
            }
        });
    }
});

function dumpMod(name) {
    var mod = Process.findModuleByName(name);
    if (!mod) { console.log('  module ' + name + ' not found yet, retrying...'); return; }
    ['r-x','r--','rw-'].forEach(function(perm) {
        var ranges = mod.enumerateRanges(perm);
        ranges.forEach(function(r) {
            var buf = r.base.readByteArray(r.size);
            var fn = '/data/local/tmp/skb_' + perm.replace('-','') + '_' + r.base.toString(16) + '.bin';
            var f = new File(fn, 'wb'); f.write(buf); f.close();
            console.log('[OK] ' + perm + ' -> ' + fn + ' (' + r.size + 'B)');
        });
    });
}

console.log('[+] all hooks installed');
"""

def on_msg(msg, data):
    if msg['type'] == 'send': print(msg['payload'])

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
session = dev.attach(2001)

script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
time.sleep(2)

# 重启 app
os.system('"D:\\Emu\\nx_main\\adb.exe" -s 127.0.0.1:7555 shell "su -c \\"am force-stop com.target.app; sleep 1; am start -n com.target.app/.modular.main.activity.EntryActivity\\""')
print('[!] app restarted, waiting 20s for loads...')

time.sleep(20)
session.detach()
print('[+] done. checking dump files...')
os.system('"D:\\Emu\\nx_main\\adb.exe" -s 127.0.0.1:7555 shell "su -c \\"ls -la /data/local/tmp/skb_* 2>/dev/null | head -10\\""')