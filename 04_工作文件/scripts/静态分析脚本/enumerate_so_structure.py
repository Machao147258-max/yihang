from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
from pathlib import Path
import os, re

root=Path(r'C:\Users\dev\Desktop\样本\libs_arm64')
out=[]
for fn in sorted(root.glob('*.so')):
    d=fn.read_bytes(); out.append(f'## {fn.name}\n')
    if d[:4]!=b'\x7fELF': out.append('NOT ELF\n'); continue
    with fn.open('rb') as f:
        e=ELFFile(f)
        out += [f'- size: {len(d):,} bytes', f'- class: ELF{e.elfclass}', f'- machine: {e["e_machine"]}', f'- type: {e["e_type"]}', f'- entry: 0x{e["e_entry"]:x}', f'- program_headers: {e.num_segments()}', f'- sections: {e.num_sections()}']
        loads=[]
        for i,p in enumerate(e.iter_segments()):
            if p['p_type']=='PT_LOAD':
                fl=''.join(c for bit,c in [(4,'R'),(2,'W'),(1,'X')] if p['p_flags']&bit) or '-'
                loads.append(f'  - #{i}: VA 0x{p["p_vaddr"]:x}, file 0x{p["p_offset"]:x}, filesz 0x{p["p_filesz"]:x}, memsz 0x{p["p_memsz"]:x}, {fl}')
        out.append('- PT_LOAD:\n'+'\n'.join(loads))
        dyn=e.get_section_by_name('.dynamic')
        if dyn:
            vals=[]
            for t in dyn.iter_tags():
                if t.entry.d_tag in ('DT_NEEDED','DT_SONAME','DT_INIT','DT_FINI','DT_INIT_ARRAY','DT_INIT_ARRAYSZ','DT_FINI_ARRAY','DT_FINI_ARRAYSZ','DT_RELA','DT_RELASZ','DT_JMPREL','DT_PLTRELSZ','DT_PLTREL'):
                    val=getattr(t,'needed',None) or getattr(t,'soname',None) or getattr(t.entry,'d_val',None)
                    vals.append(f'{t.entry.d_tag}={val}')
            out.append('- dynamic: '+(', '.join(vals) if vals else 'present'))
        else: out.append('- dynamic: absent')
        for secname in ['.init','.fini','.init_array','.fini_array','.dynsym','.dynstr','.rela.dyn','.rela.plt','.plt','.text']:
            sec=e.get_section_by_name(secname)
            if sec: out.append(f'- {secname}: VA 0x{sec["sh_addr"]:x}, file 0x{sec["sh_offset"]:x}, size 0x{sec["sh_size"]:x}')
        dynsym=e.get_section_by_name('.dynsym')
        syms=[]
        if dynsym:
            for s in dynsym.iter_symbols():
                if s.name: syms.append(f'{s.name}@0x{s["st_value"]:x}')
        out.append(f'- named_dynsym: {len(syms)}')
        if syms: out.append('  '+', '.join(syms[:40]))
    strings=[(m.start(),m.group().decode('ascii','replace')) for m in re.finditer(rb'[ -~]{5,}',d)]
    keys=['JNI_OnLoad','RegisterNatives','Java_','Internal_','RSA','SM2','SM3','SM4','AES','DES','WBC','OpenMemory','DexFile','TracerPid','ptrace','/proc/self/maps','dlopen','mprotect']
    hits=[]
    for k in keys:
        n=sum(1 for _,s in strings if k.lower() in s.lower())
        if n: hits.append(f'{k}({n})')
    out.append('- static_features: '+(', '.join(hits) if hits else 'none'))
    out.append('')
path=root/'all_so_elf_structure.md'
path.write_text('# 样本样本全部 SO ELF 结构（纯静态）\n\n'+ '\n'.join(out),encoding='utf-8')
print(path)
print('files=',len(list(root.glob('*.so'))))
