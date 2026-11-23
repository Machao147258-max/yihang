#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SO 自动化分析工具
功能：
1. 解析 ELF 头（架构、段权限）
2. 提取动态符号表（JNI 函数）
3. 扫描敏感字符串
4. 检测壳特征（UPX、反调试）
"""

import os
import struct
import re
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional

class ELFAnalyzer:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = open(filepath, 'rb').read()
        self.is_64bit = self.data[4] == 2
        self.is_le = self.data[5] == 1
        
    def parse_elf_header(self) -> Dict:
        """解析 ELF 头"""
        info = {
            'class': 'ELF64' if self.is_64bit else 'ELF32',
            'data': 'LSB' if self.is_le else 'MSB',
            'type': struct.unpack_from('<H', self.data, 16)[0],
            'machine': struct.unpack_from('<H', self.data, 18)[0],
        }
        
        arch_map = {
            0x03: 'x86',
            0x3e: 'x86_64',
            0x28: 'ARM',
            0xb7: 'AArch64',
        }
        info['arch'] = arch_map.get(info['machine'], f"Unknown({info['machine']:#x})")
        
        if self.is_64bit:
            info['entry'] = struct.unpack_from('<Q', self.data, 24)[0]
            info['phoff'] = struct.unpack_from('<Q', self.data, 32)[0]
            info['shoff'] = struct.unpack_from('<Q', self.data, 40)[0]
            info['phentsize'] = struct.unpack_from('<H', self.data, 54)[0]
            info['phnum'] = struct.unpack_from('<H', self.data, 56)[0]
            info['shentsize'] = struct.unpack_from('<H', self.data, 58)[0]
            info['shnum'] = struct.unpack_from('<H', self.data, 60)[0]
            info['shstrndx'] = struct.unpack_from('<H', self.data, 62)[0]
        
        return info
    
    def parse_segments(self) -> List[Dict]:
        """解析程序头（段信息）"""
        if not self.is_64bit:
            return []
        
        segments = []
        phoff = struct.unpack_from('<Q', self.data, 32)[0]
        phentsize = struct.unpack_from('<H', self.data, 54)[0]
        phnum = struct.unpack_from('<H', self.data, 56)[0]
        
        PT_LOAD = 1
        PF_R, PF_W, PF_X = 4, 2, 1
        
        for i in range(phnum):
            off = phoff + i * phentsize
            p_type = struct.unpack_from('<I', self.data, off)[0]
            
            if p_type == PT_LOAD:
                p_flags = struct.unpack_from('<I', self.data, off + 4)[0]
                p_vaddr = struct.unpack_from('<Q', self.data, off + 16)[0]
                p_filesz = struct.unpack_from('<Q', self.data, off + 32)[0]
                p_memsz = struct.unpack_from('<Q', self.data, off + 40)[0]
                
                perms = ('r' if p_flags & PF_R else '-') + \
                        ('w' if p_flags & PF_W else '-') + \
                        ('x' if p_flags & PF_X else '-')
                
                segments.append({
                    'perms': perms,
                    'vaddr': p_vaddr,
                    'filesz': p_filesz,
                    'memsz': p_memsz,
                })
        
        return segments
    
    def extract_symbols(self) -> List[str]:
        """提取动态符号表（通过字符串扫描）"""
        symbols = []
        
        # 方法1: 扫描 Java_ 开头的字符串（JNI 函数）
        pattern = rb'Java_[a-zA-Z_][a-zA-Z0-9_]*'
        for m in re.finditer(pattern, self.data):
            sym = m.group().decode('ascii', errors='replace')
            if sym not in symbols:
                symbols.append(sym)
        
        # 方法2: 扫描 JNI_OnLoad 等
        for name in [b'JNI_OnLoad', b'JNI_OnUnload']:
            if name in self.data:
                symbols.append(name.decode('ascii'))
        
        return symbols
    
    def scan_strings(self, min_len: int = 6) -> List[str]:
        """扫描可打印字符串"""
        strings = []
        pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
        
        for m in re.finditer(pattern, self.data):
            s = m.group().decode('ascii', errors='replace')
            strings.append(s)
        
        return strings
    
    def detect_shell(self) -> Dict:
        """检测壳特征"""
        features = {
            'upx': False,
            'ptrace': False,
            'anti_debug': [],
        }
        
        # UPX 检测
        if b'UPX!' in self.data or b'UPX0' in self.data or b'UPX1' in self.data:
            features['upx'] = True
        
        # 反调试字符串
        keywords = [
            b'ptrace', b'frida', b'xposed', b'magisk', b'hook',
            b'debug', b'strace', b'ltrace', b'gdb', b'cydia',
            b'supersu', b'root', b'kernel', b'shell', b'terminal',
        ]
        
        for kw in keywords:
            if kw.lower() in self.data.lower():
                features['anti_debug'].append(kw.decode('ascii', errors='replace'))
                if kw == b'ptrace':
                    features['ptrace'] = True
        
        return features
    
    def analyze(self) -> Dict:
        """完整分析"""
        return {
            'file': os.path.basename(self.filepath),
            'size': len(self.data),
            'elf': self.parse_elf_header(),
            'segments': self.parse_segments(),
            'symbols': self.extract_symbols(),
            'shell': self.detect_shell(),
        }


def print_report(analysis: Dict):
    """打印分析报告"""
    print(f"\n{'='*70}")
    print(f"文件: {analysis['file']}")
    print(f"大小: {analysis['size']:,} bytes")
    print(f"{'='*70}\n")
    
    # ELF 头
    elf = analysis['elf']
    print(f"架构: {elf['arch']} ({elf['class']})")
    print(f"入口: {elf['entry']:#x}")
    print(f"段数: {elf['phnum']}")
    
    # 段信息
    print(f"\n--- 段权限 ---")
    for seg in analysis['segments']:
        print(f"  {seg['perms']} vaddr={seg['vaddr']:#x} filesz={seg['filesz']:#x} memsz={seg['memsz']:#x}")
    
    # 壳检测
    shell = analysis['shell']
    print(f"\n--- 壳检测 ---")
    print(f"  UPX: {'是' if shell['upx'] else '否'}")
    print(f"  ptrace: {'是' if shell['ptrace'] else '否'}")
    if shell['anti_debug']:
        print(f"  反调试关键词: {', '.join(shell['anti_debug'])}")
    
    # JNI 符号
    jni_syms = [s for s in analysis['symbols'] if s.startswith('Java_')]
    print(f"\n--- JNI 导出函数 ({len(jni_syms)}) ---")
    for sym in jni_syms[:20]:
        print(f"  {sym}")
    if len(jni_syms) > 20:
        print(f"  ... 还有 {len(jni_syms) - 20} 个")
    
    # 敏感字符串
    sensitive = []
    keywords = ['root', 'frida', 'xposed', 'magisk', 'hook', 'debug', 'ptrace',
                'encrypt', 'decrypt', 'key', 'password', 'secret', 'token',
                'shell', 'kbcrypter', 'dex', 'check', 'detect']
    
    for s in analysis['symbols']:
        if any(kw in s.lower() for kw in keywords):
            sensitive.append(s)
    
    if sensitive:
        print(f"\n--- 敏感符号 ({len(sensitive)}) ---")
        for s in sensitive[:30]:
            print(f"  {s}")


def main():
    if len(sys.argv) < 2:
        print("用法: python so_analyzer.py <so_file> [so_file2 ...]")
        print("示例: python so_analyzer.py libKbCrypter.so libcoredex-x86.so")
        sys.exit(1)
    
    for filepath in sys.argv[1:]:
        if not os.path.exists(filepath):
            print(f"文件不存在: {filepath}")
            continue
        
        try:
            analyzer = ELFAnalyzer(filepath)
            analysis = analyzer.analyze()
            print_report(analysis)
        except Exception as e:
            print(f"分析失败 {filepath}: {e}")


if __name__ == '__main__':
    main()
