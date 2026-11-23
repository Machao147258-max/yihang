Java.perform(function () {
    var cls = Java.use("com.target.app.modular.main.activity.EntryActivity");
    var methods = cls.class.getDeclaredMethods();
    console.log("=== EntryActivity methods ===");
    for (var i = 0; i < methods.length; i++) {
        console.log(methods[i].toString());
    }
    // 父类
    var sc = cls.class.getSuperclass();
    console.log("=== superclass: " + sc.getName() + " ===");
    var sm = sc.getDeclaredMethods();
    for (var j = 0; j < sm.length; j++) {
        var s = sm[j].toString();
        if (s.indexOf("onCreate") !== -1 || s.indexOf("init") !== -1 || s.indexOf("check") !== -1 || s.indexOf("safe") !== -1 || s.indexOf("root") !== -1) {
            console.log(s);
        }
    }
});
