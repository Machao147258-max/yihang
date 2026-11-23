#!/usr/bin/env python3
"""暴力尝试解密 KbcrypterCrypter 密文"""
import struct, collections, math, sys

CIPHER = 'C:/Users/dev/Desktop/样本/libs_arm64/libKbCrypter.so'
corejni = 'C:/Users/dev/Desktop/样本/libs_arm64/libcorejni.so'

def load(path):
    return open(path, 'rb').read()

def entropy(data):
    c = collections.Counter(data)
    return -sum((v/len(data))*math.log2(v/len(data)) for v in c.values()) if data else 0

skb = load(CIPHER)
dxj = load(corejni)
ct = skb[0xc000:0x9c000]
print(f'ciphertext: {len(ct)} bytes, entropy: {entropy(ct):.2f}')

# 从 libcorejni 提取各区间作为 XOR key
trials = []
for off, sz in [(0x13000,256), (0x13000,128), (0x13068,64), (0x13100,256)]:
    trials.append(('corejni+0x%x'%off, dxj[off:off+sz]))
trials.append(('dex_part', load('C:/Users/dev/Desktop/样本/classes.dex')[:50000]))

# 对 0xc000 前 512B（ELF 元数据）试解密，看熵是否显著降低
print('\n=== XOR 暴力测试（前 512B 熵下降检测）===')
for name, key in trials:
    if not key: continue
    for rep in [1,2,4,8]:
        klen = len(key) * rep
        k = (key * rep)[:klen]
        out = bytes(ct[i] ^ k[i % len(k)] for i in range(min(len(ct), 4096)))
        e = entropy(out[:512])
        print(f'  {name} X{rep:2d} key={klen:4d}B  entropy={e:.2f}', end='')
        if e < 6.5: print(' <<< LOW', end='')
        print()

# 尝试异或 0x13000 的每字节为 XOR key 的单字节
print('\n=== 单字节 XOR ===')
for x in range(256):
    out = bytes(b ^ x for b in ct[:512])
    e = entropy(out)
    if e < 6.0:
        print(f'  XOR 0x{x:02x}: entropy={e:.2f} <<<')