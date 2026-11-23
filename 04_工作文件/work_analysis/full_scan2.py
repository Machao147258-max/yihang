import frida, time, subprocess, sys

ADB = '"D:\\Emu\\nx_main\\adb.exe" -s 127.0.0.1:7555'

jscode = """
var ranges = Process.enumerateRanges('r--');
ranges = ranges.concat(Process.enumerateRanges('rw-'));
ranges = ranges.concat(Process.enumerateRanges('r-x'));

var patterns = ['64 65 78 0a 30 33 35', '64 65 78 0a 30 33 39', '64 65 78 0a 30 33 37', '64 65 78 0a 30 33 36'];
var hits = [];
var idx = 0;

ranges.forEach(function(r) {
    if (r.size < 4096 || r.size > 60000000) return;
    patterns.forEach(function(pat) {
        try {
            var results = Memory.scanSync(r.base, r.size, pat);
            results.forEach(function(res) {
                var sz = res.address.add(0x20).readU32();
                if (sz > 1000 && sz < 60000000) {
                    try {
                        var buf = res.address.readByteArray(sz);
                        var fn = '/data/local/tmp/ds_' + idx + '_' + sz + '.dex';
                        var f = new File(fn, 'wb'); f.write(buf); f.close();
                        send('HIT ' + idx + ' @' + res.address + ' sz=' + sz + ' perm=' + r.protection + ' file=' + (r.file?r.file.path:'anon') + ' -> ' + fn);
                        idx++;
                    } catch(e2) {
                        send('HIT(no-save) @' + res.address + ' sz=' + sz + ' err=' + e2);
                    }
                }
            });
        } catch(e) {}
    });
});
send('DONE, saved ' + idx);
"""

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)

pid = int(sys.argv[1])
print(f'PID={pid}')
dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
session = dev.attach(pid)
script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
time.sleep(60)
session.detach()
print('done')
