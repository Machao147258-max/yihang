import frida, time, sys

jscode = """
var ranges = Process.enumerateRanges('r--').concat(Process.enumerateRanges('rw-')).concat(Process.enumerateRanges('r-x'));
var pats = ['64 65 78 0a 30 33 35','64 65 78 0a 30 33 36','64 65 78 0a 30 33 37','64 65 78 0a 30 33 38','64 65 78 0a 30 33 39'];
var out = [];
ranges.forEach(function(r) {
    if (r.size < 4096 || r.size > 60000000) return;
    pats.forEach(function(pat) {
        try {
            Memory.scanSync(r.base, r.size, pat).forEach(function(x) {
                try {
                    var h = x.address.readByteArray(0x70);
                    var dv = new DataView(h);
                    var fsz = dv.getUint32(0x20, true);
                    var cls = dv.getUint32(0x60, true);
                    var strs = dv.getUint32(0x38, true);
                    if (cls > 500 && fsz < 60000000) {
                        out.push('BIGDEX @' + x.address + ' file_size=' + fsz + ' classes=' + cls + ' strings=' + strs + ' perm=' + r.protection + ' file=' + (r.file?r.file.path:'anon'));
                    }
                } catch(e) {}
            });
        } catch(e) {}
    });
});
send('big dex count: ' + out.length);
out.forEach(function(o) { send(o); });
"""

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)

pid = int(sys.argv[1])
dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
session = dev.attach(pid)
script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
time.sleep(45)
session.detach()
print('done')
