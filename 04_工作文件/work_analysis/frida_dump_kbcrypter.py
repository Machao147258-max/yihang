#!/usr/bin/env python3
"""frida dump KbcrypterCrypter.so 解密后内存"""
import frida, sys, os, time

DEVICE_PORT = '127.0.0.1:8080'
TARGET = 'com.target.app'
DUMP_DIR = '/data/local/tmp/'
LOCAL_DIR = 'C:/Users/dev/Desktop/work_analysis/dumps/'

jscode = """
'use strict';

Interceptor.attach(Module.findExportByName('linker64', '__dl__Z9do_dlopenPKcPK17android_dlextinfoPKv'), {
    onEnter: function(args) {
        var path = args[0].readCString();
        if (path && (path.includes('KbcrypterCrypter') || path.includes('kbcrypter') || path.includes('shell'))) {
            console.log('[!] dlopen:', path);
            this.dump = true;
        }
    },
    onLeave: function(retval) {
        if (this.dump && retval.toInt32() !== 0) {
            console.log('[+] lib loaded, base=' + Module.findBaseAddress('libKbCrypter.so'));
            var mod = Process.findModuleByName('libKbCrypter.so');
            if (mod) {
                console.log('[+] module size=0x' + mod.size.toString(16));
                var ranges = mod.enumerateRanges('r-x');
                ranges.forEach(function(r) {
                    var buf = r.base.readByteArray(r.size);
                    var fn = '/data/local/tmp/kbcrypter_' + r.base.toString(16) + '.bin';
                    var f = new File(fn, 'wb'); f.write(buf); f.close();
                    console.log('[OK] dumped', r.size, '->', fn);
                });
                ranges = mod.enumerateRanges('r--');
                ranges.forEach(function(r) {
                    var buf = r.base.readByteArray(r.size);
                    var fn = '/data/local/tmp/kbcrypter_r_' + r.base.toString(16) + '.bin';
                    var f = new File(fn, 'wb'); f.write(buf); f.close();
                    console.log('[OK] dumped', r.size, '->', fn);
                });
                ranges = mod.enumerateRanges('rw-');
                ranges.forEach(function(r) {
                    var buf = r.base.readByteArray(r.size);
                    var fn = '/data/local/tmp/kbcrypter_rw_' + r.base.toString(16) + '.bin';
                    var f = new File(fn, 'wb'); f.write(buf); f.close();
                    console.log('[OK] dumped', r.size, '->', fn);
                });
            }
        }
    }
});

// 也 hook ddopen 所以不依赖触发
console.log('[+] hook ready');
"""

def on_message(msg, data):
    if msg['type'] == 'send':
        print(msg['payload'])

def main():
    # 连接 nosuke frida-server
    mgr = frida.get_device_manager()
    dev = mgr.add_remote_device(DEVICE_PORT)
    print(f'[+] connected to {DEVICE_PORT}')
    
    # 附加进程
    session = dev.attach(TARGET)
    session.on('detached', lambda reason: print(f'[!] detached: {reason}'))
    print(f'[+] attached to {TARGET}, PID={dev.get_process(TARGET).pid}')
    
    # 创建脚本
    script = session.create_script(jscode)
    script.on('message', on_message)
    script.load()
    
    # 等 hook 安装完
    time.sleep(1)
    print('[+] script loaded, waiting for KbcrypterCrypter load...')
    
    # 触发键盘: 启动一个密码相关 activity
    os.system('adb -s 127.0.0.1:7555 shell \"su -c \\\"am start -n com.target.app/.modular.mine.activity.GestureLoginActivity\\\"\" 2>/dev/null')
    
    # 等 10 秒看有没有 dump 出来
    for i in range(20):
        time.sleep(1)
        if i % 5 == 4:
            print(f'  waiting {i+1}s...')
    
    session.detach()
    print('[+] done')

if __name__ == '__main__':
    main()