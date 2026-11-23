// 样本 app Java 层检测点定位：hook File/Runtime/exec + 栈回溯拿类名
Java.perform(function () {
    function stack() {
        try {
            var t = Java.use("java.lang.Thread");
            var cur = t.currentThread();
            var st = cur.getStackTrace();
            var out = [];
            for (var i = 0; i < st.length && i < 12; i++) {
                var e = st[i];
                var cls = e.getClassName();
                if (cls.indexOf("java.lang") !== 0 && cls.indexOf("frida") === -1) {
                    out.push(cls + "." + e.getMethodName() + ":" + e.getLineNumber());
                }
            }
            return out.join(" <- ");
        } catch (e) { return "stack-err:" + e; }
    }

    // File.exists/存在性检测
    var File = Java.use("java.io.File");
    var exists = File.exists.overload();
    exists.implementation = function () {
        var r = exists.call(this);
        var p = "";
        try { p = this.getAbsolutePath().toString(); } catch (e) {}
        var low = p.toLowerCase();
        if (low.indexOf("/su") !== -1 || low.indexOf("magisk") !== -1 || low.indexOf("ksu") !== -1 ||
            low.indexOf("frida") !== -1 || low.indexOf("xposed") !== -1 || low.indexOf("zygisk") !== -1 ||
            low.indexOf("superuser") !== -1 || low.indexOf("busybox") !== -1) {
            console.log("[DETECT File.exists] " + p + " -> " + r);
            console.log("  STACK: " + stack());
        }
        return r;
    };

    // Runtime.exec / ProcessBuilder
    var Runtime = Java.use("java.lang.Runtime");
    try {
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            console.log("[DETECT exec] " + cmd);
            console.log("  STACK: " + stack());
            return Runtime.exec.overload("java.lang.String").call(this, cmd);
        };
    } catch (e) {}
    var PB = Java.use("java.lang.ProcessBuilder");
    PB.start.implementation = function () {
        try {
            console.log("[DETECT ProcessBuilder] " + this.command().toString());
            console.log("  STACK: " + stack());
        } catch (e) {}
        return PB.start.call(this);
    };

    // SystemProperties
    var SP = Java.use("android.os.SystemProperties");
    for (var i = 0; i < SP.get.overloads.length; i++) {
        (function (ov) {
            ov.implementation = function () {
                var v = "";
                try { v = String(ov.apply(this, arguments)); } catch (e) {}
                var k = "";
                try { k = String(arguments[0]); } catch (e) {}
                if (k.indexOf("qemu") !== -1 || k.indexOf("abi") !== -1 || k.indexOf("selinux") !== -1 ||
                    k.indexOf("debuggable") !== -1 || k.indexOf("secure") !== -1 || k.indexOf("model") !== -1 ||
                    k.indexOf("manufacturer") !== -1 || k.indexOf("hardware") !== -1) {
                    console.log("[DETECT prop] " + k + " = " + v);
                    console.log("  STACK: " + stack());
                }
                return v;
            };
        })(SP.get.overloads[i]);
    }

    console.log("[+] java probe ready");
});
