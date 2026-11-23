// Frida 脚本: 监控 libKbCrypter.so 加载 + dump 解密后的代码段
// 用法: frida -H 127.0.0.1:8080 -l dump_kbcrypter.js com.target.app

'use strict';

var dumpDir = '/data/local/tmp/';

Interceptor.attach(Module.findExportByName('linker64', '__dl__Z9do_dlopenPKcPK17android_dlextinfoPKv'), {
    onEnter: function(args) {
        var path = args[0].readCString();
        if (path && path.includes('KbcrypterCrypter')) {
            console.log('[!] dlopen detected:', path);
            this.dump = true;
        }
    },
    onLeave: function(retval) {
        if (this.dump && retval.toInt32() !== 0) {
            var mod = Process.findModuleByName('libKbCrypter.so');
            if (mod) {
                console.log('[+] module loaded @ 0x' + mod.base.toString(16) + ' - 0x' + mod.size);
                // dump r-x 代码段
                var ranges = mod.enumerateRanges('r-x');
                ranges.forEach(function(r) {
                    var buf = r.base.readByteArray(r.size);
                    var fname = dumpDir + 'kbcrypter_rx_' + r.base.toString(16) + '.bin';
                    var f = new File(fname, 'wb');
                    f.write(buf);
                    f.flush();
                    f.close();
                    console.log('[+] dumped', r.size, 'bytes to', fname);
                });
                // 也 dump rw- 段
                ranges = mod.enumerateRanges('rw-');
                ranges.forEach(function(r) {
                    var buf = r.base.readByteArray(r.size);
                    var fname = dumpDir + 'kbcrypter_rw_' + r.base.toString(16) + '.bin';
                    var f = new File(fname, 'wb');
                    f.write(buf);
                    f.flush();
                    f.close();
                    console.log('[+] dumped', r.size, 'bytes to', fname);
                });
            }
        }
    }
});

console.log('[+] hook installed, waiting for KbcrypterCrypter...');