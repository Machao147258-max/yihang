console.log('[+] HOOK LOADED at app start');

// hook fopen
var fopen = Module.findExportByName('libc.so', 'fopen');
if (fopen) {
    console.log('[+] fopen @ ' + fopen);
    Interceptor.attach(fopen, {
        onEnter: function(args) {
            try {
                var path = args[0].readCString() || '';
                var mode = '';
                try { mode = args[1].readCString() || ''; } catch(e) {}
                if (path.indexOf('target') >= 0 || path.indexOf('app') >= 0 ||
                    path.indexOf('Kbcrypter') >= 0 || path.indexOf('shell') >= 0 ||
                    path.indexOf('Coredex') >= 0 || path.indexOf('corejni') >= 0 ||
                    path.indexOf('.so') >= 0 || path.indexOf('assets/') >= 0) {
                    console.log('[fopen] ' + path + ' [' + mode + ']');
                }
            } catch(e) {}
        }
    });
}

// hook mmap - large mappings
var mmap = Module.findExportByName('libc.so', 'mmap');
if (mmap) {
    Interceptor.attach(mmap, {
        onEnter: function(args) {
            var size = args[1].toInt32();
            var prot = args[2].toInt32();
            var flags = args[3].toInt32();
            if (size > 50000 && size < 20000000) {
                console.log('[mmap] sz=' + size + ' prot=' + prot.toString(16) + ' flags=' + flags.toString(16));
            }
        }
    });
}

// hook lseek - large seeks
var lseek = Module.findExportByName('libc.so', 'lseek');
if (lseek) {
    Interceptor.attach(lseek, {
        onEnter: function(args) {
            var off = args[1].toInt32();
            if (off > 500000 || off < -1) {
                console.log('[lseek] offset=' + off + ' whence=' + args[2].toInt32());
            }
        }
    });
}

// hook read - large reads
var read = Module.findExportByName('libc.so', 'read');
if (read) {
    Interceptor.attach(read, {
        onEnter: function(args) {
            var count = args[2].toInt32();
            if (count > 50000) {
                console.log('[read] size=' + count);
            }
        }
    });
}

console.log('[+] ALL HOOKS INSTALLED');