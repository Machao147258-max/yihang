import frida, time

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
PID = 14439

jscode = """
var dexfile = Process.findModuleByName('libdexfile.so');
if (!dexfile) { console.log('dexfile not found'); }

var syms = dexfile.enumerateExports();
var targets = [];
syms.forEach(function(s) {
    var n = s.name;
    if (n.indexOf('DexFile') >= 0 || n.indexOf('OpenCommon') >= 0 || n.indexOf('OpenOne') >= 0 || n.indexOf('RegisterDex') >= 0) {
        targets.push(s);
    }
});

console.log('=== DexFile exports ===');
targets.forEach(function(s) {
    console.log(s.name + ' @ ' + s.address);
});

var art = Process.findModuleByName('libart.so');
if (art) {
    console.log('\\n=== ART exports ===');
    var count = 0;
    art.enumerateExports().forEach(function(s) {
        if (s.name.indexOf('DexFile') >= 0 || s.name.indexOf('RegisterDex') >= 0 || s.name.indexOf('OpenDexFiles') >= 0) {
            console.log(s.name);
            count++;
        }
    });
    if (count == 0) console.log('none found');
}
"""

def on_msg(msg, data):
    p = msg.get('payload', '')
    if p: print(p)

session = dev.attach(PID)
script = session.create_script(jscode)
script.on('message', on_msg)
script.load()
time.sleep(5)
session.detach()