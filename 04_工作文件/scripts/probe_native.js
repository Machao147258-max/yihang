// probe_native.js — 纯 native 检测点探测(nosuke 兼容:只用实例方法 API)
// 覆盖 libc: open/access/stat/lstat/readlinkat/__system_property_get/connect
function hookSym(modName, sym, onEnter) {
    var m = Process.findModuleByName(modName);
    if (!m) { console.log("[-] module not found: " + modName); return; }
    var addr = m.findExportByName(sym);
    if (!addr) { console.log("[-] sym not found: " + modName + "!" + sym); return; }
    Interceptor.attach(addr, { onEnter: onEnter });
    console.log("[+] hooked " + modName + "!" + sym + " @ " + addr);
}

function readStr(p) {
    if (p.isNull()) return "";
    try { return p.readCString() || ""; } catch (e) { return "<err>"; }
}

var PAT = ["/su", "magisk", "kernelsu", "supolicy", "superuser", "busybox",
           "xposed", "lspose", "frida", "zygisk", "shamiko", "riru", "substrate",
           "re.frida", "/data/local/tmp", "linjector", "gum-js", "tq_su", "sbin",
           "/proc/self/maps", "/proc/self/status", "/proc/self/task", "/proc/self/cmdline",
           "/proc/self/fd", "/proc/net/tcp", "cmdline", "/dev/knl", "/dev/qemu", "/sys/devices"];

function checkPath(s) {
    if (!s) return false;
    s = s.toLowerCase();
    for (var i = 0; i < PAT.length; i++) if (s.indexOf(PAT[i]) !== -1) return true;
    return false;
}

// 文件类探测
hookSym("libc.so", "open", function (a) {
    var p = readStr(a[0]);
    if (checkPath(p)) {
        console.log("[open] " + p);
        var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
        for (var i = 0; i < bt.length && i < 12; i++) {
            var m = Process.findModuleByAddress(bt[i]);
            var off = (m && bt[i].compare(m.base) >= 0) ? bt[i].sub(m.base).toString(16) : "?";
            var sym = DebugSymbol.fromAddress(bt[i]);
            console.log("    <- " + (m ? m.name + " +0x" + off : "?") + (sym.name ? "  (" + sym.name + ")" : ""));
        }
    }
});
hookSym("libc.so", "access", function (a) {
    var p = readStr(a[0]);
    if (checkPath(p)) console.log("[access] " + p + " mode=" + a[1]);
});
hookSym("libc.so", "stat", function (a) {
    var p = readStr(a[0]);
    if (checkPath(p)) console.log("[stat] " + p);
});
hookSym("libc.so", "lstat", function (a) {
    var p = readStr(a[0]);
    if (checkPath(p)) console.log("[lstat] " + p);
});

// getprop 全量(属性名是检测指纹的关键)
hookSym("libc.so", "__system_property_get", function (a) {
    var name = readStr(a[0]);
    if (name) console.log("[prop] " + name);
});

// connect: 抓端口扫描(27042/31337/45681)与 DNS 行为
hookSym("libc.so", "connect", function (a) {
    var fd = a[0].toInt32();
    try {
        var sockaddr = a[1];
        var family = sockaddr.readU16();
        if (family === 2) { // AF_INET
            var port = (sockaddr.add(2).readU16() >> 8) | ((sockaddr.add(2).readU8() & 0xff) << 8);
            try { port = sockaddr.add(2).readU16(); port = ((port >> 8) & 0xff) | ((port << 8) & 0xff00); } catch (e) {}
            var ip = sockaddr.add(4).readU32();
            console.log("[connect] fd=" + fd + " port=" + port + " ip=0x" + ip.toString(16));
        } else if (family === 10) { // AF_INET6
            console.log("[connect6] fd=" + fd);
        }
    } catch (e) {}
});

// socket 创建(可观察频率)
hookSym("libc.so", "socket", function (a) {
    var af = a[0].toInt32(), type = a[1].toInt32(), proto = a[2].toInt32();
    if (proto === 0 && (type & 0xFF) === 1) return; // TCP 太多,略;UDP/raw 打印
    console.log("[socket] af=" + af + " type=" + type + " proto=" + proto);
});

console.log("[+] native probes ready");
