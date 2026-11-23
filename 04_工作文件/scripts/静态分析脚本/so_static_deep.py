import os, re, struct, json
from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_LITTLE_ENDIAN, CS_MODE_64
from elftools.elf.elffile import ELFFile

ROOT=r'C:\Users\dev\Desktop\样本'
FILES=[
 ('libcorejni.so', ROOT+r'\libs_arm64\libcorejni.so','arm64'),
 ('libKbCrypter.so', ROOT+r'\libs_arm64\libKbCrypter.so','arm64'),
 ('libsecenv.so', ROOT+r'\libs_arm64\libsecenv.so','arm64'),
 ('libcoredex-x86.so', ROOT+r'\libs_arm64\libcoredex-x86.so','x86'),
 ('libcoredex-x86.decrypted.so', ROOT+r'\某加固壳成果\libcoredex-x86.decrypted.so','x86'),
]

def u32(d,o): return struct.unpack_from('<I',d,o)[0]
def u64(d,o): return struct.unpack_from('<Q',d,o)[0]
def map_va(ph,va):
 for p in ph:
  if p['vaddr'] <= va < p['vaddr']+p['memsz']:
   x=p['offset']+(va-p['vaddr'])
   if x < p['file_end']: return x
 return None

report=[]
for name,fn,arch in FILES:
 report.append('\n=== '+name+' ===')
 d=open(fn,'rb').read(); report.append(f'file_size={len(d)}')
 if d[:4]!=b'\x7fELF': report.append('NOT ELF'); continue
 cls=d[4]; mach=struct.unpack_from('<H',d,18)[0]; entry=u64(d,24) if cls==2 else u32(d,24)
 phoff=u64(d,32); phents=u16=d[54]|(d[55]<<8); phnum=d[56]|(d[57]<<8)
 ph=[]
 for i in range(phnum):
  o=phoff+i*phents
  if cls==2:
   ptype=u32(d,o); flags=u32(d,o+4); off=u64(d,o+8); va=u64(d,o+16); fs=u64(d,o+32); ms=u64(d,o+40)
  else: continue
  ph.append({'type':ptype,'flags':flags,'offset':off,'vaddr':va,'filesz':fs,'memsz':ms,'file_end':off+fs})
 report.append(f'class={cls} machine=0x{mach:x} entry=0x{entry:x} phnum={phnum}')
 report.append('PT_LOAD='+str([(hex(x['vaddr']),hex(x['offset']),hex(x['filesz']),hex(x['memsz']),x['flags']) for x in ph if x['type']==1]))
 # dynamic tags and symbol-like strings
 with open(fn,'rb') as f:
  try:
   e=ELFFile(f)
   dyn=e.get_section_by_name('.dynamic')
   if dyn:
    report.append('dynamic_tags='+str([(t.entry.d_tag, str(t.entry.d_val) if hasattr(t.entry,'d_val') else '') for t in dyn.iter_tags()][:40]))
   else: report.append('dynamic_section=absent')
  except Exception as ex: report.append('elftools_error='+repr(ex))
 # disassemble executable loads correctly
 for p in ph:
  if p['type']!=1 or not (p['flags']&1) or p['offset']>=len(d): continue
  blob=d[p['offset']:min(len(d),p['offset']+p['filesz'])]
  md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN) if arch=='arm64' else Cs(CS_ARCH_X86,CS_MODE_64)
  ins=list(md.disasm(blob,p['vaddr']))
  report.append(f'EXEC va={p["vaddr"]:#x} off={p["offset"]:#x} size={len(blob):#x} decoded={len(ins)}')
  # relevant call/branch and literal loading instructions
  rel=[]
  for i in ins:
   text=i.mnemonic+' '+i.op_str
   if any(k in text.lower() for k in ['bl ','blr','call','jmp','adr','adrp','ldr','lea']): rel.append(f'{i.address:#x}: {text}')
  report.extend(rel[:180])
 # strings with file offset and candidate VA
 ss=[(m.start(),m.group().decode('ascii','replace')) for m in re.finditer(rb'[ -~]{5,}',d)]
 for key in ['JNI_OnLoad','RegisterNatives','OpenMemory','OpenCommon','InMemoryDexClassLoader','Internal_SM2','Internal_RSA','Internal_SM4','Shell_AES','Shell_WBC','SM3_hash','assets','TracerPid','ptrace','/proc/self/maps']:
  hs=[]
  for off,s in ss:
   if key.lower() in s.lower():
    va=None
    for p in ph:
     if p['offset']<=off<p['offset']+p['filesz']: va=p['vaddr']+off-p['offset']; break
    hs.append((hex(off),hex(va) if va is not None else None,s[:120]))
  if hs: report.append(key+'='+str(hs[:20]))
open(ROOT+r'\so_static_deep_report.txt','w',encoding='utf-8').write('\n'.join(report))
print('written',ROOT+r'\so_static_deep_report.txt','lines',len(report))
