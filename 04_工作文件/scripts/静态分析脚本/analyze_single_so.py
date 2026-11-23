from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import struct, re

fn=r'C:\Users\dev\Desktop\样本\libs_arm64\libcorejni.so'
d=open(fn,'rb').read()
out=[]

out.append('# libcorejni.so 完整静态分析报告')
out.append(f'\n## 基本信息')
out.append(f'- 文件路径: `{fn}`')
out.append(f'- 文件大小: {len(d):,} bytes ({len(d)/1024/1024:.2f} MB)')
out.append(f'- MD5: {__import__("hashlib").md5(d).hexdigest()}')
out.append(f'- SHA256: {__import__("hashlib").sha256(d).hexdigest()}')

with open(fn,'rb') as f:
    e=ELFFile(f)
    out.append(f'\n## ELF 头部')
    out.append(f'- ELF 类: ELF{e.elfclass}')
    out.append(f'- 数据编码: {"LSB" if e.little_endian else "MSB"}')
    out.append(f'- 机器架构: {e["e_machine"]}')
    out.append(f'- 文件类型: {e["e_type"]}')
    out.append(f'- 入口地址: 0x{e["e_entry"]:x}')
    out.append(f'- Program Headers: {e.num_segments()}')
    out.append(f'- Section Headers: {e.num_sections()}')
    
    out.append(f'\n## Program Headers (PT_LOAD)')
    for i,p in enumerate(e.iter_segments()):
        if p['p_type']=='PT_LOAD':
            fl=''.join(c for bit,c in [(4,'R'),(2,'W'),(1,'X')] if p['p_flags']&bit) or '-'
            out.append(f'### 段 #{i}')
            out.append(f'- 虚拟地址: 0x{p["p_vaddr"]:x}')
            out.append(f'- 文件偏移: 0x{p["p_offset"]:x}')
            out.append(f'- 文件大小: 0x{p["p_filesz"]:x} ({p["p_filesz"]:,} bytes)')
            out.append(f'- 内存大小: 0x{p["p_memsz"]:x} ({p["p_memsz"]:,} bytes)')
            out.append(f'- 权限: {fl}')
            out.append(f'- 对齐: 0x{p["p_align"]:x}')
            if p['p_memsz']>p['p_filesz']:
                out.append(f'- **注意**: memsz > filesz，有 BSS 区域 ({p["p_memsz"]-p["p_filesz"]:,} bytes)')
    
    out.append(f'\n## 动态段 (DT_*)')
    dyn=e.get_section_by_name('.dynamic')
    if dyn:
        for t in dyn.iter_tags():
            tag=t.entry.d_tag
            if tag in ('DT_NEEDED','DT_SONAME','DT_INIT','DT_FINI','DT_INIT_ARRAY','DT_INIT_ARRAYSZ','DT_FINI_ARRAY','DT_FINI_ARRAYSZ','DT_RELA','DT_RELASZ','DT_JMPREL','DT_PLTRELSZ','DT_PLTREL','DT_SYMBOLIC','DT_BIND_NOW','DT_FLAGS_1'):
                val=getattr(t,'needed',None) or getattr(t,'soname',None) or getattr(t.entry,'d_val',None)
                out.append(f'- {tag}: {val}')
    else:
        out.append('- 无 .dynamic 段')
    
    out.append(f'\n## 关键 Section')
    for secname in ['.init','.fini','.init_array','.fini_array','.dynsym','.dynstr','.rela.dyn','.rela.plt','.plt','.text','.rodata','.data','.bss']:
        sec=e.get_section_by_name(secname)
        if sec:
            out.append(f'### {secname}')
            out.append(f'- 虚拟地址: 0x{sec["sh_addr"]:x}')
            out.append(f'- 文件偏移: 0x{sec["sh_offset"]:x}')
            out.append(f'- 大小: 0x{sec["sh_size"]:x} ({sec["sh_size"]:,} bytes)')
            out.append(f'- 类型: {sec["sh_type"]}')
            out.append(f'- 标志: {sec["sh_flags"]}')
    
    out.append(f'\n## 动态符号表 (.dynsym)')
    dynsym=e.get_section_by_name('.dynsym')
    if dynsym:
        syms=list(dynsym.iter_symbols())
        out.append(f'- 符号总数: {len(syms)}')
        named=[s for s in syms if s.name]
        out.append(f'- 有名称符号: {len(named)}')
        if named:
            out.append('\n### 前 50 个符号')
            for s in named[:50]:
                out.append(f'- {s.name} @ 0x{s["st_value"]:x} (type={s["st_info"]["type"]}, bind={s["st_info"]["bind"]})')
    else:
        out.append('- 无 .dynsym 段')

out.append(f'\n## 字符串扫描')
strings=[(m.start(),m.group().decode('ascii','replace')) for m in re.finditer(rb'[ -~]{5,}',d)]
out.append(f'- 总字符串数: {len(strings)}')
out.append(f'\n### 关键特征字符串')
keys=['JNI_OnLoad','RegisterNatives','Java_','Internal_','RSA','SM2','SM3','SM4','AES','DES','WBC','OpenMemory','DexFile','TracerPid','ptrace','/proc/self/maps','dlopen','mprotect','assets','classes%d.dex']
for k in keys:
    hits=[(hex(off),s[:100]) for off,s in strings if k.lower() in s.lower()]
    if hits:
        out.append(f'\n#### {k} ({len(hits)} 处)')
        for off,s in hits[:10]:
            out.append(f'- {off}: `{s}`')

out.append(f'\n## 反汇编：入口点 0xb10')
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
# 入口点 0xb10 在第一个 PT_LOAD 内，VA 0x0-0x2ca0
# 文件偏移 = 0xb10 - 0x0 + 0x0 = 0xb10
off=0xb10
insns=list(md.disasm(d[off:off+0x200],0xb10))
out.append(f'- 反汇编范围: 0xb10 - 0xd10 ({len(insns)} 条指令)')
for i in insns[:40]:
    out.append(f'  0x{i.address:08x}: {i.mnemonic:<8} {i.op_str}')

out.append(f'\n## 反汇编：关键函数 0x1184')
# 0x1184 也在第一个 PT_LOAD 内
off=0x1184
insns=list(md.disasm(d[off:off+0x400],0x1184))
out.append(f'- 反汇编范围: 0x1184 - 0x1584 ({len(insns)} 条指令)')
for i in insns[:60]:
    out.append(f'  0x{i.address:08x}: {i.mnemonic:<8} {i.op_str}')

out.append(f'\n## 全局数据区域 0x13000-0x130a0')
# 0x13000 在第二个 PT_LOAD 内，VA 0x12d08，文件偏移 0x2d08
# 文件偏移 = 0x13000 - 0x12d08 + 0x2d08 = 0x13000
off=0x13000
data=d[off:off+0xa0]
out.append(f'- 数据范围: 0x13000 - 0x130a0 ({len(data)} bytes)')
out.append(f'- 十六进制:')
for i in range(0,len(data),16):
    hex_part=' '.join(f'{b:02x}' for b in data[i:i+16])
    ascii_part=''.join(chr(b) if 32<=b<127 else '.' for b in data[i:i+16])
    out.append(f'  0x{0x13000+i:08x}: {hex_part:<48} {ascii_part}')

out.append(f'\n## 总结')
out.append('- 这是一个 AArch64 动态库，入口点 0xb10')
out.append('- 代码段很小（0x2ca0 bytes），数据段很大（0x1bf3e0 bytes）')
out.append('- 包含 JNI_OnLoad，但没有显式 Java_* 导出符号')
out.append('- 使用 dlopen、mprotect、/proc/self/maps，有反调试特征')
out.append('- 0x1184 处有 RC4 类 KSA 结构（256 字节状态表初始化）')
out.append('- 0x13068 处可能是 key 或状态表数据')

path=r'C:\Users\dev\Desktop\样本\libs_arm64\libcorejni_full_analysis.md'
open(path,'w',encoding='utf-8').write('\n'.join(out))
print(path)
print('lines=',len(out))
