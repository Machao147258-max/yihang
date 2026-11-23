#!/usr/bin/env python3
"""frida 在运行进程里 dump libcorejni 的运行时 key table"""
import frida, time, os

jscode = """
'use strict';

// 找 libcorejni.so 数据段映射
var maps = Process.enumerateRanges({protection: 'rw-', coalesce: false});
var libcorejniData = null;
maps.forEach(function(r) {
    // 在进程 maps 里找 libcorejni 的数据段
    if (!r.file) return;
    if (r.file.path.indexOf('libcorejni') >= 0 || r.file.path.indexOf('Coredex') >= 0) {
        console.log('[!] found ' + r.file.path + ' @ ' + r.base + ' size=' + r.size);
        libcorejniData = r;
    }
});

if (libcorejniData) {
    // dump 整个数据段
    var buf = libcorejniData.base.readByteArray(libcorejniData.size);
    var fn = '/data/local/tmp/corejni_data.bin';
    var f = new File(fn, 'wb'); f.write(buf); f.close();
    console.log('[+] dumped ' + libcorejniData.size + ' bytes to ' + fn);
    
    // 也找下 key table 位置 (从文件偏移 0x13000 映射到内存的偏移)
    var keyTableOff = 0x13000;
    if (keyTableOff < libcorejniData.size) {
        var keyByte = libcorejniData.base.add(keyTableOff).readByteArray(256);
        var kfn = '/data/local/tmp/corejni_keytable.bin';
        var kf = new File(kfn, 'wb'); kf.write(keyByte); kf.close();
        console.log('[+] key table dumped to ' + kfn);
    }
} else {
    // fallback: 搜内存中的 0x13000 特征
    console.log('[!] libcorejni data range not found, searching memory...');
    maps.forEach(function(r) {
        if (r.size > 262144) return;
        try {
            var buf = r.base.readByteArray(Math.min(r.size, 4096));
            var s = Array.from(new Uint8Array(buf));
            // 找 ee23bf9d 特征
            for (var i = 0; i < s.length - 4; i++) {
                if (s[i] === 0xee && s[i+1] === 0x23 && s[i+2] === 0xbf) {
                    console.log('[!] key table pattern @ ' + r.base + '+' + i.toString(16));
                    var out = r.base.add(i).readByteArray(256);
                    var fn = '/data/local/tmp/keytable_found.bin';
                    var f = new File(fn, 'wb'); f.write(out); f.close();
                    console.log('[+] saved to ' + fn);
                    break;
                }
            }
        } catch(e) {}
    });
}
console.log('[+] done');
"""

def on_msg(msg, data):
    p = msg.get('payload','')
    if p: print(p)

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
session = dev.attach(2001)
script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
time.sleep(5)
session.detach()

# pull
os.system('"D:\\Emu\\nx_main\\adb.exe" -s 127.0.0.1:7555 pull /data/local/tmp/corejni_data.bin C:\\Users\\dev\\Desktop\\work_analysis\\dumps\\ 2>nul')
os.system('"D:\\Emu\\nx_main\\adb.exe" -s 127.0.0.1:7555 pull /data/local/tmp/corejni_keytable.bin C:\\Users\\dev\\Desktop\\work_analysis\\dumps\\ 2>nul')
os.system('"D:\\Emu\\nx_main\\adb.exe" -s 127.0.0.1:7555 pull /data/local/tmp/keytable_found.bin C:\\Users\\dev\\Desktop\\work_analysis\\dumps\\ 2>nul')

# check
import os.path as p
for fn in ['corejni_data.bin','corejni_keytable.bin','keytable_found.bin']:
    fp = 'C:/Users/dev/Desktop/work_analysis/dumps/' + fn
    if os.path.exists(fp):
        d = open(fp,'rb').read()
        print(fn, 'size:', len(d), 'first 32:', d[:32].hex())
        # 检查是否与静态一致
        static = open('C:/Users/dev/Desktop/样本/libs_arm64/libcorejni.so','rb').read()
        if len(d) > 0x13000 and d[0x13000:0x13010] == static[0x13000:0x13010]:
            print('  SAME AS STATIC - not patched')
        else:
            print('  DIFFERENT FROM STATIC - runtime patched!')