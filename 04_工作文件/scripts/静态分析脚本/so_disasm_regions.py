from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_LITTLE_ENDIAN, CS_MODE_64
from elftools.elf.elffile import ELFFile
import os

ROOT=r'C:\Users\dev\Desktop\样本'
TARGETS=[
 ('libcorejni.so',ROOT+r'\libs_arm64\libcorejni.so','arm64',[0xb10,0x1184,0x1600,0x1c00]),
 ('libKbCrypter.so',ROOT+r'\libs_arm64\libKbCrypter.so','arm64',[0xacc0,0x5220]),
 ('libcoredex-x86.so',ROOT+r'\libs_arm64\libcoredex-x86.so','x86',[0x0,0x1782]),
]

def va_to_file(phdrs, va):
    for p in phdrs:
        if p['p_type']=='PT_LOAD' and p['p_vaddr'] <= va < p['p_vaddr']+p['p_filesz']:
            return p['p_offset'] + va - p['p_vaddr']
    return None

out=[]
for name,fn,arch,addrs in TARGETS:
    d=open(fn,'rb').read()
    with open(fn,'rb') as f:
        e=ELFFile(f); ph=list(e.iter_segments())
    out.append('\n=== '+name+' ===')
    for va in addrs:
        off=va_to_file(ph,va)
        out.append(f'-- VA {va:#x} -> file offset {off if off is not None else None} --')
        if off is None: continue
        if arch=='arm64': md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); size=0x180
        else: md=Cs(CS_ARCH_X86,CS_MODE_64); size=0x240
        ins=list(md.disasm(d[off:min(len(d),off+size)],va))
        for i in ins:
            out.append(f'{i.address:08x}: {i.mnemonic:<8} {i.op_str}')
        if not ins: out.append('[no instructions decoded]')
path=ROOT+r'\so_disasm_key_regions.txt'
open(path,'w',encoding='utf-8').write('\n'.join(out))
print('written',path,'lines',len(out))
