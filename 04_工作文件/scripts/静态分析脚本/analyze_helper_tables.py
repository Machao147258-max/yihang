from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import struct, re, hashlib

ROOT=r'C:\Users\dev\Desktop\样本\libs_arm64'
FILES=['libcoredex.so','libcorejni.so']

def u64(d,o): return struct.unpack_from('<Q',d,o)[0]
def va_file(ph,va):
    for p in ph:
        if p['p_type']=='PT_LOAD' and p['p_offset'] <= 0xffffffff and p['p_vaddr'] <= va < p['p_vaddr']+p['p_filesz']:
            return p['p_offset'] + va-p['p_vaddr']
    return None

out=[]
for name in FILES:
 fn=ROOT+'\\'+name; d=open(fn,'rb').read(); out.append('=== '+name+' ===')
 with open(fn,'rb') as f:
  e=ELFFile(f); ph=list(e.iter_segments()); out.append(f'md5={hashlib.md5(d).hexdigest()}')
  for p in ph:
   if p['p_type']=='PT_LOAD': out.append(f'LOAD va={p["p_vaddr"]:#x} off={p["p_offset"]:#x} fs={p["p_filesz"]:#x} ms={p["p_memsz"]:#x} flags={p["p_flags"]}')
 # Decode executable first segment only, identify calls and PC-relative data refs
 md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
 p=[x for x in ph if x['p_type']=='PT_LOAD' and x['p_flags']&1][0]
 blob=d[p['p_offset']:p['p_offset']+p['p_filesz']]
 ins=list(md.disasm(blob,p['p_vaddr']))
 out.append(f'instructions={len(ins)}')
 for i in ins:
  if i.mnemonic in ('bl','blr','br') or i.mnemonic in ('adr','adrp') or ('[' in i.op_str and any(x in i.mnemonic for x in ['ldr','str'])):
   out.append(f'{i.address:#x}: {i.mnemonic:<6} {i.op_str}')
 # inspect pointer words around suspected table VAs
 for base in [0x14000,0x15000,0x13000,0x15080,0x40000,0x47000]:
  off=va_file(ph,base)
  if off is None: continue
  out.append(f'POINTERS va={base:#x} file={off:#x}')
  for j in range(0,0x100,8):
   if off+j+8>len(d): break
   v=u64(d,off+j)
   if v: out.append(f'  {base+j:#x}: {v:#018x}')
 # string candidates
 ss=[(m.start(),m.group().decode('ascii','replace')) for m in re.finditer(rb'[ -~]{5,}',d)]
 for k in ['JNI_OnLoad','dlopen','mprotect','/proc/self/maps','DexFile','OpenMemory','libcorejni','libcoredex']:
  hs=[f'{o:#x}: {s[:120]}' for o,s in ss if k.lower() in s.lower()]
  if hs: out.append(k+':\n'+'\n'.join(hs[:20]))
path=ROOT+'\\libcoredex_pointer_analysis.md';open(path,'w',encoding='utf-8').write('\n'.join(out));print(path)
