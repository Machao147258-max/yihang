import frida, time, subprocess, sys, struct

jscode = """
var ranges = Process.enumerateRanges('r--').concat(Process.enumerateRanges('rw-'));
var pat1 = '63 6f 6d 2f 79 61 6f 64 75';  // "com/target"
var hits = [];
ranges.forEach(function(r) {
    if (r.size < 4096 || r.size > 60000000) return;
    try {
        var res = Memory.scanSync(r.base, r.size, pat1);
        res.forEach(function(x) {
            hits.push(x.address + ' perm=' + r.protection + ' file=' + (r.file?r.file.path:'anon'));
        });
    } catch(e) {}
});
send('HITS: ' + hits.length);
hits.slice(0, 40).forEach(function(h) { send(h); });
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
time.sleep(30)
session.detach()
print('done')
