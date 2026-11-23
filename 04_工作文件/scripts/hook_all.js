// hook EntryActivity 全部方法 + 常见检测 API，动态定位检测链
Java.perform(function () {
    var cls = Java.use("com.target.app.modular.main.activity.EntryActivity");
    var methods = cls.class.getDeclaredMethods();
    for (var i = 0; i < methods.length; i++) {
        var m = methods[i];
        var name = m.getName();
        var mods = m.getModifiers();
        if (java.lang.reflect.Modifier.isStatic(mods)) continue;
        try {
            var params = m.getParameterTypes();
            var argTypes = [];
            for (var j = 0; j < params.length; j++) argTypes.push(params[j].getName());
            var overloads = cls[name].overloads;
            for (var k = 0; k < overloads.length; k++) {
                (function (ov, n) {
                    ov.implementation = function () {
                        var args = [];
                        for (var a = 0; a < arguments.length; a++) {
                            try { args.push(String(arguments[a])); } catch (e) { args.push("?"); }
                        }
                        var r = ov.apply(this, arguments);
                        console.log("[SPLASH." + n + "] args=[" + args.join(",") + "] ret=" + r);
                        return r;
                    };
                })(overloads[k], name);
            }
        } catch (e) {}
    }
    console.log("[+] EntryActivity all methods hooked");

    // 常见 root 检测输入
    var File = Java.use("java.io.File");
    File.exists.overload().implementation = function () {
        var p = this.getAbsolutePath().toString();
        var r = File.exists.overload().call(this);
        var low = p.toLowerCase();
        if (low.indexOf("su") !== -1 || low.indexOf("magisk") !== -1 || low.indexOf("ksu") !== -1 ||
            low.indexOf("frida") !== -1 || low.indexOf("xposed") !== -1) {
            console.log("[ROOT-CHECK File.exists] " + p + " -> " + r);
        }
        return r;
    };
    console.log("[+] File.exists hooked");
});
