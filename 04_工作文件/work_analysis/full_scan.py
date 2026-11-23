import frida, time, subprocess, os

ADB = '"D:\\Emu\\nx_main\\adb.exe" -s 127.0.0.1:7555'

jscode = """
var ranges = Process.enumerateRanges('r--');
ranges = ranges.concat(Process.enumerateRanges('rw-'));
ranges = ranges.concat(Process.enumerateRanges('r-x'));

// dex magic 扫描
var patterns = [
    ['dex\\n035', '64 65 78 0a 30 33 35'],
    ['dex\\n039', '64 65 78 0a 30 33 39'],
    ['dex\\n037', '64 65 78 0a 30 33 37'],
];

var hits = [];

ranges.forEach(function(r) {
    if (r.size < 4096 || r.size > 60000000) return;
    patterns.forEach(function(p) {
        try {
            var results = Memory.scanSync(r.base, r.size, p[1]);
            results.forEach(function(res) {
                // 读 dex size
                var sz = res.address.add(0x20).readU32();
                if (sz > 1000 && sz < 60000000) {
                    hits.push({addr: res.address, size: sz, magic: p[0], perm: r.protection, file: r.file ? r.file.path : 'anon'});
                }
            });
        } catch(e) {}
    });
});

send('total hits: ' + hits.length);
hits.forEach(function(h, i) {
    send(i + ': ' + h.magic + ' @ ' + h.addr + ' size=' + h.size + ' perm=' + h.perm + ' file=' + h.file);
});

// dump 每个 hit
hits.forEach(function(h, i) {
    try {
        var buf = h.addr.readByteArray(h.size);
        var fn = '/data/local/tmp/dexscan_' + i + '_' + h.size + '.dex';
        var f = new File(fn, 'wb'); f.write(buf); f.close();
        send('SAVED ' + fn);
    } catch(e) {
        send('save fail ' + i + ': ' + e);
    }
});
"""

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
res = subprocess.check_output(f'{ADB} shell "su -c pidof com.target.app"', shell=True).decode().strip()
pid = int(res.split()[0])
print(f'PID={pid}')

session = dev.attach(pid)
script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
time.sleep(40)
session.detach()
print('done')
