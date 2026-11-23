from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64_const import ARM64_OP_IMM
import re

fn='C:/Users/dev/Desktop/样本/libs_arm64/libcoredex.so'
d=open(fn,'rb').read(); md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
start,end=0x2cd0,0x3400
ins=list(md.disasm(d[start:end],start)); by={i.address:i for i in ins}
leaders={start}
for i in ins:
    if i.mnemonic in ('b','b.eq','b.ne','b.lt','b.le','b.gt','b.ge','b.hi','b.hs','b.lo','b.ls','cbz','cbnz','tbz','tbnz'):
        if i.operands and i.operands[-1].type==ARM64_OP_IMM:
            leaders.add(i.operands[-1].imm)
        nxt=i.address+4
        if nxt<end: leaders.add(nxt)
leaders=sorted(x for x in leaders if start<=x<end)
blocks=[]
for idx,l in enumerate(leaders):
    r=leaders[idx+1] if idx+1<len(leaders) else end
    body=[i for i in ins if l<=i.address<r]
    if body: blocks.append((l,r,body))

def targets(i):
    return [x.operands[-1].imm] if i.operands and i.operands[-1].type==ARM64_OP_IMM else []

out=['# libcoredex.so 混淆流 CFG 候选（纯静态）','',f'范围: 0x{start:x}-0x{end:x}',f'指令数: {len(ins)}',f'基本块候选: {len(blocks)}','']
for l,r,b in blocks:
    last=b[-1]; ts=targets(last)
    kind=''
    if last.mnemonic.startswith('b') or last.mnemonic.startswith('cb'):
        kind='branch'
    if any(i.mnemonic=='blr' for i in b): kind+=' indirect-call'
    if any(i.mnemonic=='br' for i in b): kind+=' indirect-jump'
    if any(i.mnemonic=='eor' for i in b): kind+=' xor'
    if any(i.mnemonic=='strb' for i in b): kind+=' byte-write'
    out.append(f'## block 0x{l:x}-0x{r:x} {kind}')
    out.append(f'- last: {last.mnemonic} {last.op_str}')
    if ts: out.append('- targets: '+', '.join(hex(x) for x in ts))
    # compact instructions
    out.append('- ops: '+ ' | '.join(i.mnemonic+' '+i.op_str for i in b[:8]))
    out.append('')
# algorithm markers
out += ['## 静态模式标记','', '- 256-byte state initialization: `strb ...; cmp x1,#0x100; b.ne`', '- KSA-like: `ldrb` from state/key, add, `and #0xff`, two `strb` swaps', '- PRGA-like: input `ldrb`, state lookups, add/index, `eor`, output write', '- dispatcher-like: repeated status comparisons with constants `0x15/0x46/0x105/0x111`', '', '## 结论边界','', '该报告只建立线性反汇编范围内的基本块候选。由于存在间接跳转和混淆状态变量，不能把所有块都视为真实执行路径；算法判断仍需结合调用者、状态变量和数据流确认。']
path='C:/Users/dev/Desktop/样本/工作文件/静态SO分析/libcoredex_cfg_static.md';open(path,'w',encoding='utf-8').write('\n'.join(out));print(path, 'blocks',len(blocks))
