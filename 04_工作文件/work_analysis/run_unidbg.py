#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unidbg 分析脚本 - 样本 app 壳对抗
目标: 绕过某加固壳壳的反调试，分析邦 cle 安全键盘加密逻辑
"""

import os
import sys

# unidbg 路径
UNIDBG_PATH = r"D:\逆向工具\unidbg"
CLASSES_PATH = os.path.join(UNIDBG_PATH, "unidbg-android", "target", "classes")
M2_PATH = r"C:\Users\dev\.m2\repository"

# 构建 classpath
CP_ITEMS = [
    os.path.join(CLASSES_PATH, "android"),
    os.path.join(CLASSES_PATH, "com"),
    os.path.join(CLASSES_PATH, "net"),
    os.path.join(UNIDBG_PATH, "unidbg-android", "target", "classes"),
    os.path.join(M2_PATH, "com", "github", "unidb", "unidbg-api", "0.9.10-SNAPSHOT", "unidbg-api-0.9.10-SNAPSHOT.jar"),
    os.path.join(M2_PATH, "com", "github", "unidb", "unidbg-android", "0.9.10-SNAPSHOT", "unidbg-android-0.9.10-SNAPSHOT.jar"),
    os.path.join(M2_PATH, "com", "github", "unidb", "unidbg-dynarmic", "0.9.10-SNAPSHOT", "unidbg-dynarmic-0.9.10-SNAPSHOT.jar"),
    os.path.join(M2_PATH, "net", "otherplan", "libandroidemu64", "0.9.10-SNAPSHOT", "libandroidemu64-0.9.10-SNAPSHOT.jar"),
    os.path.join(M2_PATH, "net", "otherplan", "unicorn", "0.9.10-SNAPSHOT", "unicorn-0.9.10-SNAPSHOT.jar"),
    os.path.join(M2_PATH, "com", "github", "keystoneengine", "keystone", "0.9.7", "keystone-0.9.7.jar"),
    os.path.join(M2_PATH, "net", "java", "jna", "jna", "5.10.0", "jna-5.10.0.jar"),
    os.path.join(M2_PATH, "net", "java", "jna", "jna-platform", "5.10.0", "jna-platform-5.10.0.jar"),
    os.path.join(M2_PATH, "com", "github", "unidb", "capstone", "3.1.8", "capstone-3.1.8.jar"),
    os.path.join(M2_PATH, "com", "alibaba", "fastjson", "1.2.83", "fastjson-1.2.83.jar"),
    os.path.join(M2_PATH, "org", "apache", "commons", "commons-lang3", "3.12.1", "commons-lang3-3.12.1.jar"),
    os.path.join(M2_PATH, "org", "apache", "commons", "commons-io", "2.11.0", "commons-io-2.11.0.jar"),
    os.path.join(M2_PATH, "com", "beust", "jcommander", "1.82", "jcommander-1.82.jar"),
    os.path.join(M2_PATH, "org", "yaml", "snakeyaml", "1.30", "snakeyaml-1.30.jar"),
    r"C:\Users\dev\Desktop\unidbg",
]

CP = ";".join(CP_ITEMS)

# Java 源码
JAVA_SRC = r"""
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.UnicornBackendFactory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.api.*;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.Module;

import java.io.File;

public class BankAnalyzer {
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    public BankAnalyzer(String soPath) {
        // 创建模拟器 (arm64)
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.target.app")
                .build();

        // 设置内存
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        // 创建 VM
        vm = emulator.createDalvikVM(new File("C:\\Users\\dev\\Desktop\\样本\\base.apk"));
        vm.setVerbose(true);

        // 加载 so
        module = vm.loadLibrary(new File(soPath), false);
    }

    public void run() {
        System.out.println("[*] Module base = 0x" + Long.toHexString(module.base));

        // 调用 JNI_OnLoad
        System.out.println("[*] Calling JNI_OnLoad...");
        vm.callJNI_OnLoad(emulator, module);

        // 列出所有 JNI 函数
        System.out.println("[*] Available JNI functions:");
        for (String sym : module.getSymbolNames()) {
            if (sym.contains("Java_")) {
                System.out.println("  " + sym);
            }
        }
    }

    public static void main(String[] args) {
        String soPath = "C:\\Users\\dev\\Desktop\\样本\\libs_arm64\\libKbCrypter.so";
        BankAnalyzer analyzer = new BankAnalyzer(soPath);
        analyzer.run();
    }
}
"""

def write_java():
    """写 Java 源码"""
    java_path = r"C:\Users\dev\Desktop\work_analysis\BankAnalyzer.java"
    os.makedirs(os.path.dirname(java_path), exist_ok=True)
    
    with open(java_path, 'w', encoding='utf-8') as f:
        f.write(JAVA_SRC)
    
    print(f"[+] Java 源码: {java_path}")
    return java_path

def compile_java(java_path):
    """编译 Java"""
    class_path = r"C:\Users\dev\Desktop\work_analysis"
    
    cmd = f'javac -encoding UTF-8 -cp "{CP}" -d "{class_path}" "{java_path}"'
    print(f"[*] 编译: {cmd}")
    
    result = os.system(cmd)
    if result != 0:
        print(f"[!] 编译失败: {result}")
        return False
    
    print("[+] 编译成功")
    return True

def run_java():
    """运行 Java"""
    class_path = r"C:\Users\dev\Desktop\work_analysis"
    
    cmd = f'java -cp "{class_path};{CP}" BankAnalyzer'
    print(f"[*] 运行: {cmd}")
    
    result = os.system(cmd)
    return result == 0

def main():
    print("="*70)
    print("unidbg 样本 app 壳分析")
    print("="*70)
    
    # 检查 so 文件
    so_path = r"C:\Users\dev\Desktop\样本\libs_arm64\libKbCrypter.so"
    if not os.path.exists(so_path):
        print(f"[!] so 文件不存在: {so_path}")
        return
    
    print(f"[*] 目标 so: {so_path}")
    print(f"[*] 大小: {os.path.getsize(so_path):,} bytes")
    
    # 写 Java
    java_path = write_java()
    
    # 编译
    if not compile_java(java_path):
        return
    
    # 运行
    run_java()

if __name__ == '__main__':
    main()
