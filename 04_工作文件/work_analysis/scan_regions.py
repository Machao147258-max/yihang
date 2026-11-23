import frida, time, sys

jscode = """
var ranges = Process.enumerateRanges('r--').concat(Process.enumerateRanges('rw-'));
var pat = '63 6f 6d 2f 79 61 6f 64 75';  // com/target
var byRegion = {};
ranges.forEach(function(r) {
    if (r.size < 4096 || r.size > 60000000) return;
    try {
        var res = Memory.scanSync(r.base, r.size, pat);
        if (res.length > 0) {
            var key = r.base + ' size=' + r.size + ' perm=' + r.protection + ' file=' + (r.file?r.file.path:'anon');
            byRegion[key] = res.length;
        }
    } catch(e) {}
});
var keys = Object.keys(byRegion);
send('regions with hits: ' + keys.length);
keys.forEach(function(k) { send(byRegion[k] + '  ' + k); });
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
