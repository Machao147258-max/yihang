// 药都农商样本 root 检测点探测脚本
// 用法: frida -H 127.0.0.1:45681 -p <PID> -l probe_root_detect.js
Java.perform(function () {
    function log(tag, msg) { console.log("[+] " + tag + ": " + msg); }

    // 1. File.exists — 扫 su / magisk 等敏感路径
    var File = Java.use("java.io.File");
    var exists = File.exists.overload();
    exists.implementation = function () {
        var r = exists.call(this);
        try {
            var p = this.getAbsolutePath().toString();
            var low = p.toLowerCase();
            var pats = ["/su", "magisk", "kernelsu", "supolicy", "superuser", "busybox",
                        "xposed", "lsp", "frida", "zygisk", "shamiko", "riru", "substrate"];
            for (var i = 0; i < pats.length; i++) {
                if (low.indexOf(pats[i]) !== -1) { log("File.exists", p + " -> " + r); break; }
            }
        } catch (e) {}
        return r;
    };

    // 2. Runtime.exec — 执行 su / getprop / ls 等命令
    var Runtime = Java.use("java.lang.Runtime");
    var sigs = ["java.lang.String", "[Ljava.lang.String;"];
    for (var i = 0; i < sigs.length; i++) {
        (function (sig) {
            Runtime.exec.overload(sig).implementation = function (cmd) {
                var c = (typeof cmd === "string") ? cmd : Java.array("java.lang.String", cmd).join(" ");
                log("Runtime.exec", c);
                return Runtime.exec.overload(sig).call(this, cmd);
            };
        })(sigs[i]);
    }

    // 3. ProcessBuilder.start
    var PB = Java.use("java.lang.ProcessBuilder");
    PB.start.implementation = function () {
        try { log("ProcessBuilder.start", this.command().toString()); } catch (e) {}
        return PB.start.call(this);
    };

    // 4. SystemProperties.get — getprop 读取(设备指纹/模拟器特征)
    var SP = Java.use("android.os.SystemProperties");
    for (var i = 0; i < SP.get.overloads.length; i++) {
        (function (ov) {
            ov.implementation = function () {
                var v = "";
                try { v = ov.apply(this, arguments); } catch (e) {}
                try {
                    var k = arguments.length > 0 ? String(arguments[0]) : "";
                    if (k.length > 0) log("getprop", k + " = " + v);
                } catch (e) {}
                return v;
            };
        })(SP.get.overloads[i]);
    }

    // 5. 应用枚举 — 扫 KernelSU/Magisk/LSPosed 等敏感包名
    var APM = Java.use("android.app.ApplicationPackageManager");
    var suspicious = ["magisk", "kernelsu", "lsp", "xposed", "hook", "root", "su_",
                      "frida", "zygisk", "shamiko", "riru", "edxposed", "virtual", "supersu"];
    ["getInstalledPackages", "getInstalledApplications"].forEach(function (m) {
        if (!APM[m]) return;
        APM[m].overloads.forEach(function (ov) {
            ov.implementation = function () {
                var res = ov.apply(this, arguments);
                try {
                    var lst = Java.cast(res, Java.use("java.util.List"));
                    var it = lst.iterator();
                    while (it.hasNext()) {
                        var obj = it.next();
                        var name = "";
                        try { name = obj.packageName.toString(); }
                        catch (e) { try { name = obj.packageName.value; } catch (e2) {} }
                        var low = name.toLowerCase();
                        for (var j = 0; j < suspicious.length; j++) {
                            if (low.indexOf(suspicious[j]) !== -1) { log("pkg-enum", name); break; }
                        }
                    }
                } catch (e) {}
                return res;
            };
        });
    });

    log("ready", "所有 hook 已安装");
});
