#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SO 敏感字符串深度扫描工具
扫描 so 文件中的敏感字符串，分类输出
"""

import os
import re
import sys
from collections import defaultdict

# 敏感关键词分类
CATEGORIES = {
    '加密算法': ['aes', 'des', 'sm4', 'tdes', 'rsa', 'sm2', 'gcm', 'cbc', 'ecb', 'encrypt', 'decrypt', 'cipher', 'crypto', 'shell'],
    '白盒': ['wb_', 'whitebox', 'white_box', 'tbox', 'sbox'],
    '反调试': ['ptrace', 'frida', 'xposed', 'magisk', 'hook', 'debug', 'strace', 'ltrace', 'gdb', 'cydia', 'supersu', 'antidebug'],
    'Root检测': ['root', 'su ', 'kernel', 'shell', 'terminal', 'busybox', 'supersu', 'magisk'],
    '环境检测': ['check', 'detect', 'protect', 'safe', 'secure', 'environment', 'tamper'],
    'JNI': ['java_', 'jni_', 'nativemethod', 'registernative'],
    '网络': ['http', 'https', 'socket', 'url', 'server', 'client', 'api', 'token'],
    '密钥': ['key', 'password', 'secret', 'salt', 'iv', 'nonce'],
    '文件操作': ['file', 'path', 'dir', 'read', 'write', 'open', 'close', 'asset'],
    '内存': ['malloc', 'free', 'mmap', 'mprotect', 'memory'],
}

def scan_strings(filepath: str, min_len: int = 4) -> list:
    """扫描可打印字符串"""
    data = open(filepath, 'rb').read()
    strings = []
    
    # 匹配 ASCII 字符串
    pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
    for m in re.finditer(pattern, data):
        s = m.group().decode('ascii', errors='replace')
        strings.append(s)
    
    return strings

def categorize_strings(strings: list) -> dict:
    """分类字符串"""
    categorized = defaultdict(list)
    
    for s in strings:
        s_lower = s.lower()
        matched = False
        
        for category, keywords in CATEGORIES.items():
            for kw in keywords:
                if kw in s_lower:
                    categorized[category].append(s)
                    matched = True
                    break
            if matched:
                break
        
        # 未分类的长字符串
        if not matched and len(s) > 10:
            categorized['其他长字符串'].append(s)
    
    return categorized

def print_report(filepath: str, categorized: dict):
    """打印报告"""
    filename = os.path.basename(filepath)
    print(f"\n{'='*70}")
    print(f"文件: {filename}")
    print(f"{'='*70}")
    
    for category in CATEGORIES.keys():
        items = categorized.get(category, [])
        if items:
            # 去重
            unique_items = sorted(set(items))
            print(f"\n--- {category} ({len(unique_items)}) ---")
            for item in unique_items[:30]:
                print(f"  {item[:100]}")
            if len(unique_items) > 30:
                print(f"  ... 还有 {len(unique_items) - 30} 个")
    
    # 其他长字符串
    others = categorized.get('其他长字符串', [])
    if others:
        unique_others = sorted(set(others))
        print(f"\n--- 其他长字符串 ({len(unique_others)}) ---")
        for item in unique_others[:20]:
            print(f"  {item[:100]}")
        if len(unique_others) > 20:
            print(f"  ... 还有 {len(unique_others) - 20} 个")

def main():
    if len(sys.argv) < 2:
        print("用法: python strings_scanner.py <so_file> [so_file2 ...]")
        sys.exit(1)
    
    for filepath in sys.argv[1:]:
        if not os.path.exists(filepath):
            print(f"文件不存在: {filepath}")
            continue
        
        try:
            strings = scan_strings(filepath)
            categorized = categorize_strings(strings)
            print_report(filepath, categorized)
        except Exception as e:
            print(f"分析失败 {filepath}: {e}")

if __name__ == '__main__':
    main()
