import frida, time

dev = frida.get_device_manager().add_remote_device('127.0.0.1:8080')
PID = 14439

jscode = """
var base = ptr('0x400020e13000');
var keyAddr = base.add(0x10068);
var key = keyAddr.readByteArray(256);
console.log('key_table @ ' + keyAddr);
var arr = new Uint8Array(key);
var s = '';
for (var i = 0; i < 32; i++) s += ('0' + arr[i].toString(16)).slice(-2) + ' ';
console.log('first 32: ' + s);

var codeAddr = ptr('0x400020e00000');
var decFunc = codeAddr.add(0x1184);
console.log('decFunc @ ' + decFunc);
var code = decFunc.readByteArray(64);
var ca = new Uint8Array(code);
var cs = '';
for (var i = 0; i < 16; i++) cs += ('0' + ca[i].toString(16)).slice(-2) + ' ';
console.log('code first 16: ' + cs);
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
