// bypass_maps.js v2 — 全面喂白食 + getprop 伪造
function hookSym(modName, sym, onEnter, onLeave) {
    var m = Process.findModuleByName(modName);
    if (!m) return;
    var addr = m.findExportByName(sym);
    if (!addr) return;
    Interceptor.attach(addr, { onEnter: onEnter, onLeave: onLeave });
    console.log("[+] hooked " + sym);
}

function readStr(p) {
    if (p.isNull()) return "";
    try { return p.readCString() || ""; } catch (e) { return ""; }
}

function checkPath(s) {
    if (!s) return false;
    s = s.toLowerCase();
    if (s.indexOf("/proc/self/maps") !== -1) return true;
    if (s.indexOf("/proc/") !== -1 && (s.indexOf("maps") !== -1 || s.indexOf("/fd") !== -1)) return true;
    if (s.indexOf("/proc/self/cmdline") !== -1) return true;
    if (s.indexOf("/proc/sys/fs/") !== -1) return true;   // ptrace_scope
    if (s === "/proc" || s === "/proc/") return true;      // 枚举进程列表
    return false;
}

function mkEnter(tag, pathArgIdx) {
    return function (a) {
        this.p = readStr(a[pathArgIdx]).slice(0, 64);
    };
}
function mkLeaveFail(tag, failval) {
    return function (r) {
        if (this.p && checkPath(this.p)) {
            console.log("[BLOCK " + tag + "] " + this.p);
            r.replace(failval);
        }
    };
}

// open 系
hookSym("libc.so", "open", mkEnter("open", 0), mkLeaveFail("open", -1));
hookSym("libc.so", "open64", mkEnter("open64", 0), mkLeaveFail("open64", -1));
hookSym("libc.so", "openat", mkEnter("openat", 1), mkLeaveFail("openat", -1));
hookSym("libc.so", "openat64", mkEnter("openat64", 1), mkLeaveFail("openat64", -1));
hookSym("libc.so", "access", mkEnter("access", 0), mkLeaveFail("access", -1));
hookSym("libc.so", "stat", mkEnter("stat", 0), mkLeaveFail("stat", -1));
hookSym("libc.so", "lstat", mkEnter("lstat", 0), mkLeaveFail("lstat", -1));
// 文件流/目录
hookSym("libc.so", "fopen", mkEnter("fopen", 0), mkLeaveFail("fopen", 0));
hookSym("libc.so", "opendir", mkEnter("opendir", 0), mkLeaveFail("opendir", 0));
hookSym("libc.so", "readlink", mkEnter("readlink", 0), mkLeaveFail("readlink", -1));
hookSym("libc.so", "readlinkat", mkEnter("readlinkat", 1), mkLeaveFail("readlinkat", -1));

// getprop 伪造:关键属性改写成真机特征
var FAKE = {
    "ro.product.cpu.abi": "arm64-v8a",
    "ro.product.cpu.abilist": "arm64-v8a,armeabi-v7a,armeabi",
    "ro.product.cpu.abilist32": "armeabi-v7a,armeabi",
    "ro.product.cpu.abilist64": "arm64-v8a",
    "ro.kernel.qemu": "0",
    "ro.boot.qemu": "0",
    "ro.bootmode": "normal",
    "ro.bootver": "Vxx.x.x.x.XXXXXX",
    "ro.build.tags": "release-keys",
    "ro.debuggable": "0",
    "ro.secure": "1",
    "gsm.version.baseband": "1.0.0",
    "ro.kernel.hardware": "qcom"
};
var gp = Process.findModuleByName("libc.so").findExportByName("__system_property_get");
Interceptor.attach(gp, {
    onEnter: function (a) {
        this.name = readStr(a[0]);
        this.buf = a[1];
    },
    onLeave: function (ret) {
        if (this.buf.isNull()) return;
        var v = FAKE[this.name];
        if (v !== undefined) {
            try {
                this.buf.writeUtf8String(v);
                ret.replace(v.length);
                console.log("[FAKE prop] " + this.name + " = " + v);
            } catch (e) {}
        } else if (this.name) {
            console.log("[prop] " + this.name + " = " + readStr(this.buf));
        }
    }
});

console.log("[+] bypass v2 ready");
