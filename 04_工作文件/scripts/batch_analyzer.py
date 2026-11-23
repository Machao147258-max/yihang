#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量 SO 分析工具
分析目录下所有 so 文件，生成综合报告
"""

import os
import sys
import re
from pathlib import Path
from datetime import datetime

def analyze_so(filepath: str) -> dict:
    """分析单个 so 文件"""
    data = open(filepath, 'rb').read()
    
    info = {
        'file': os.path.basename(filepath),
        'size': len(data),
        'arch': 'Unknown',
        'jni_functions': [],
        'sensitive_strings': [],
        'shell_features': [],
        'environment_checks': [],
    }
    
    # 架构检测
    if len(data) >= 20:
        machine = data[18] | (data[19] << 8)
        arch_map = {0x03: 'x86', 0x3e: 'x86_64', 0x28: 'ARM', 0xb7: 'AArch64'}
        info['arch'] = arch_map.get(machine, f'Unknown({machine:#x})')
    
    # JNI 函数
    jni_pattern = rb'Java_[a-zA-Z_][a-zA-Z0-9_]*'
    for m in re.finditer(jni_pattern, data):
        func = m.group().decode('ascii', errors='replace')
        if func not in info['jni_functions']:
            info['jni_functions'].append(func)
    
    # 敏感字符串
    sensitive_keywords = [
        b'ptrace', b'frida', b'xposed', b'magisk', b'hook',
        b'encrypt', b'decrypt', b'aes', b'des', b'sm4', b'rsa', b'sm2',
        b'shell', b'kbcrypter', b'whitebox', b'wb_',
        b'password', b'secret', b'key', b'token',
        b'/proc/self/', b'cmdline', b'maps',
    ]
    
    str_pattern = rb'[\x20-\x7e]{4,}'
    for m in re.finditer(str_pattern, data):
        s = m.group()
        s_lower = s.lower()
        
        for kw in sensitive_keywords:
            if kw in s_lower:
                decoded = s.decode('ascii', errors='replace')
                if decoded not in info['sensitive_strings']:
                    info['sensitive_strings'].append(decoded)
                break
    
    # 壳特征
    if b'UPX!' in data or b'UPX0' in data:
        info['shell_features'].append('UPX')
    if b'ptrace' in data:
        info['shell_features'].append('ptrace反调试')
    if b'__b_a_n_g_c_l_e__' in data:
        info['shell_features'].append('邦cle检测')
    if b'mprotect' in data:
        info['shell_features'].append('mprotect内存修改')
    
    # 环境检测
    if b'/proc/self/cmdline' in data:
        info['environment_checks'].append('/proc/self/cmdline')
    if b'/proc/self/maps' in data:
        info['environment_checks'].append('/proc/self/maps')
    if b'/proc/self/status' in data:
        info['environment_checks'].append('/proc/self/status')
    
    return info

def generate_report(results: list, output_file: str):
    """生成报告"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# SO 批量分析报告\n")
        f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"分析文件数: {len(results)}\n\n")
        
        f.write("## 概览\n\n")
        f.write("| 文件 | 架构 | 大小 | JNI函数 | 壳特征 | 环境检测 |\n")
        f.write("|------|------|------|---------|--------|----------|\n")
        
        for r in results:
            size_mb = r['size'] / 1024 / 1024
            jni_count = len(r['jni_functions'])
            shell = ', '.join(r['shell_features']) if r['shell_features'] else '-'
            env = ', '.join(r['environment_checks']) if r['environment_checks'] else '-'
            
            f.write(f"| {r['file']} | {r['arch']} | {size_mb:.2f}MB | {jni_count} | {shell} | {env} |\n")
        
        f.write("\n## 详细分析\n\n")
        
        for r in results:
            f.write(f"### {r['file']}\n\n")
            f.write(f"- **架构**: {r['arch']}\n")
            f.write(f"- **大小**: {r['size']:,} bytes ({r['size']/1024:.1f} KB)\n\n")
            
            # JNI 函数
            if r['jni_functions']:
                f.write(f"**JNI 导出函数 ({len(r['jni_functions'])})**:\n")
                for func in r['jni_functions'][:20]:
                    f.write(f"- `{func}`\n")
                if len(r['jni_functions']) > 20:
                    f.write(f"- ... 还有 {len(r['jni_functions']) - 20} 个\n")
                f.write("\n")
            
            # 壳特征
            if r['shell_features']:
                f.write(f"**壳特征**:\n")
                for feat in r['shell_features']:
                    f.write(f"- {feat}\n")
                f.write("\n")
            
            # 环境检测
            if r['environment_checks']:
                f.write(f"**环境检测**:\n")
                for check in r['environment_checks']:
                    f.write(f"- `{check}`\n")
                f.write("\n")
            
            # 敏感字符串
            if r['sensitive_strings']:
                f.write(f"**敏感字符串 ({len(r['sensitive_strings'])})**:\n")
                for s in r['sensitive_strings'][:30]:
                    f.write(f"- `{s[:80]}`\n")
                if len(r['sensitive_strings']) > 30:
                    f.write(f"- ... 还有 {len(r['sensitive_strings']) - 30} 个\n")
                f.write("\n")
            
            f.write("---\n\n")

def main():
    if len(sys.argv) < 2:
        print("用法: python batch_analyzer.py <目录路径>")
        print("示例: python batch_analyzer.py libs_arm64")
        sys.exit(1)
    
    dir_path = sys.argv[1]
    if not os.path.isdir(dir_path):
        print(f"目录不存在: {dir_path}")
        sys.exit(1)
    
    # 查找所有 so 文件
    so_files = []
    for f in os.listdir(dir_path):
        if f.endswith('.so'):
            so_files.append(os.path.join(dir_path, f))
    
    if not so_files:
        print(f"目录中没有 .so 文件: {dir_path}")
        sys.exit(1)
    
    print(f"找到 {len(so_files)} 个 so 文件，开始分析...")
    
    # 分析所有文件
    results = []
    for filepath in so_files:
        print(f"  分析: {os.path.basename(filepath)}")
        try:
            info = analyze_so(filepath)
            results.append(info)
        except Exception as e:
            print(f"  错误: {e}")
    
    # 生成报告
    output_file = os.path.join(dir_path, 'analysis_report.md')
    generate_report(results, output_file)
    
    print(f"\n分析完成！")
    print(f"报告已保存到: {output_file}")
    
    # 打印摘要
    print(f"\n{'='*70}")
    print("摘要:")
    print(f"{'='*70}")
    
    total_jni = sum(len(r['jni_functions']) for r in results)
    shell_count = sum(1 for r in results if r['shell_features'])
    env_count = sum(1 for r in results if r['environment_checks'])
    
    print(f"总文件数: {len(results)}")
    print(f"JNI 函数总数: {total_jni}")
    print(f"有壳特征: {shell_count}")
    print(f"有环境检测: {env_count}")
    
    # 列出有壳特征的
    if shell_count > 0:
        print(f"\n有壳特征的文件:")
        for r in results:
            if r['shell_features']:
                print(f"  {r['file']}: {', '.join(r['shell_features'])}")

if __name__ == '__main__':
    main()
