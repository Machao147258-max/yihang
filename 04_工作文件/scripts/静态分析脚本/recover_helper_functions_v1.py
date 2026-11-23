from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from pathlib import Path

fn=Path(r'C:\Users\dev\Desktop\样本\02_提取SO\libs_arm64\libcoredex.so')
d=fn.read_bytes(); md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
# 重点区域：按已知直接调用边界切分，不宣称覆盖全 SO
regions=[('hash_or_dispatch',0x2bf8,0x2ca8),('state_setup',0x2ca8,0x3248),('rc4_candidate',0x3248,0x33f8),('loader_init',0x33f8,0x3600),('caller_entry',0x4880,0x4960)]
out=['# libcoredex.so 第1项：函数/控制流/算法静态恢复','','样本: '+str(fn),'架构: AArch64','']
for label,s,e in regions:
 out += [f'## {label}: 0x{s:x}-0x{e:x}']
 ins=list(md.disasm(d[s:e],s)); out.append(f'- decoded instructions: {len(ins)}')
 for i in ins:
  out.append(f'0x{i.address:08x}: {i.mnemonic:<8} {i.op_str}')
 out.append('')
# direct callers using correct capstone operand type
out += ['## Direct call edges']
for target in [0x2bf8,0x2a70,0x29a0,0x32ac,0x33f8]:
 hits=[]
 for off in range(0,len(d)-4,4):
  xs=list(md.disasm(d[off:off+4],off))
  if not xs: continue
  i=xs[0]
  if i.mnemonic=='bl' and i.operands and i.operands[-1].type==2 and i.operands[-1].imm==target:
   hits.append(i.address)
 out.append(f'- 0x{target:x} <- '+(', '.join(hex(x) for x in hits) if hits else '(none)'))
out += ['', '## Static interpretation (confidence-labeled)', '', '- **High confidence**: 0x32ac–0x33e4 contains 256-byte state initialization, 8-bit index masking, state swaps and input XOR output.', '- **High confidence**: 0x2bf8–0x2ca4 is a byte-wise hash/index routine with left-shift-by-4 and high-nibble fold/XOR.', '- **Medium confidence**: 0x33f8–0x494c is an initialization/loading path that prepares 0x100/0x200/0x400-byte buffers.', '- **Not yet proven**: RC4 candidate output is the dex payload; key origin and resource mapping remain unresolved.', '', '## Completion boundary', '', 'This is a static recovery report for the selected regions, not a complete reconstruction of the entire stripped/obfuscated SO.']
outp=Path(r'C:\Users\dev\Desktop\样本\05_静态分析\libcoredex_function_recovery_v1.md'); outp.write_text('\\n'.join(out),encoding='utf-8'); print(outp)
