#!/usr/bin/env python3
"""某加固壳 so 解密引擎完整实现 — 从 libcorejni.so 反编译"""
import struct, collections, math, sys

BASE = 'C:/Users/dev/Desktop/样本/libs_arm64/'

def entropy(data):
    c = collections.Counter(data)
    return -sum((v/len(data))*math.log2(v/len(data)) for v in c.values()) if data else 99

def find_valid_arm64(data):
    """检测是否是有效 ARM64 代码"""
    stp = data[:4096].count(b'\xfd\x7b')  # stp x29, x30 常见
    stp2 = data[:4096].count(b'\xff\x83')  # stp x29, x30 另一种编码
    ret = data[:4096].count(b'\xc0\x03\x5f\xd6')  # ret
    return stp + stp2, ret

def try_rc4(data, S, key, label):
    """标准 RC4"""
    S = S[:]
    for i in range(256):
        j = (j := 0 if i == 0 else None) or 0
        # 标准 KSA
    # 重写
    S2 = S[:]
    j = 0
    for i in range(256):
        j = (j + S2[i] + key[i % len(key)]) & 0xFF
        S2[i], S2[j] = S2[j], S2[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S2[i]) & 0xFF
        S2[i], S2[j] = S2[j], S2[i]
        k = S2[(S2[i] + S2[j]) & 0xFF]
        out.append(byte ^ k)
    stp, ret = find_valid_arm64(out)
    e = entropy(out[:512])
    ok = '<<<' if stp > 5 else ''
    if stp > 0 or e < 6.0:
        print(f'  {label:40s} ent={e:.2f} stp={stp} ret={ret} {ok}')
    return bytes(out)

# 加载文件
dx = open(BASE + 'libcorejni.so', 'rb').read()
skb = open(BASE + 'libKbCrypter.so', 'rb').read()

# ===== 候选数据 =====
candidates = {}

# 1. KbcrypterCrypter 的密文段
candidates['skb_cipher'] = skb[0xc000:0x9c000]
# 2. libcorejni 数据区高熵段（可能是加密的 so）
data_sec = dx[0x12d08:]
candidates['corejni_data0-0x10000'] = data_sec[:0x10000]
candidates['corejni_data10000-20000'] = data_sec[0x10000:0x20000]
candidates['corejni_data20000-30000'] = data_sec[0x20000:0x30000]
candidates['corejni_data30000-40000'] = data_sec[0x30000:0x40000]
candidates['corejni_data40000-50000'] = data_sec[0x40000:0x50000]
candidates['corejni_data50000-60000'] = data_sec[0x50000:0x60000]
candidates['corejni_data60000-70000'] = data_sec[0x60000:0x70000]
candidates['corejni_data70000-7c000'] = data_sec[0x70000:0x7c000]
candidates['corejni_data_f0000-100000'] = data_sec[0xf0000:0x100000]

# 3. pts 资产（10MB）
pts = None
import zipfile
try:
    z = zipfile.ZipFile('C:/Users/dev/Desktop/样本/base.apk')
    pts = z.read('assets/pts')
    candidates['pts'] = pts[:0x10000]
except: pass

# ===== 密钥组合 =====
S_base = list(dx[0x13000:0x13100])  # 256B S-box

key_offsets = [0x13068, 0x13000, 0x12d08, 0x13020, 0x13080]
key_lens = [8, 16, 24, 32]

print('='*80)
print('某加固壳 so 解密引擎 — 暴力测试')
print(f'S_box unique: {len(set(S_base))}/256')
print('='*80)

for cname, cdata in candidates.items():
    if len(cdata) < 256: continue
    print(f'\n--- [{cname}] ({len(cdata)}B) ---')
    
    for koff in key_offsets:
        for klen in key_lens:
            key = list(dx[koff:koff+klen])
            if len(key) < klen: continue
            label = f'key@0x{koff:x}_{klen}B'
            
            # 变体1: 标准 RC4 (KSA=key)
            S1 = S_base[:]
            j = 0
            for i in range(256):
                j = (j + S1[i] + key[i % len(key)]) & 0xFF
                S1[i], S1[j] = S1[j], S1[i]
            i = j = 0
            out = bytearray()
            for byte in cdata[:4096]:
                i = (i + 1) & 0xFF
                j = (j + S1[i]) & 0xFF
                S1[i], S1[j] = S1[j], S1[i]
                k = S1[(S1[i] + S1[j]) & 0xFF]
                out.append(byte ^ k)
            stp, ret = find_valid_arm64(out)
            e = entropy(out[:512])
            if stp > 0 or e < 6.5:
                print(f'  [PRGA] {label:25s} ent={e:.2f} stp={stp} ret={ret} <<<')
    
    # 变体2: 只用 0x13000 S 盒做 XOR (无 KSA)
    for koff2 in [0x13000, 0x13068]:
        k = dx[koff2:koff2+256]
        for xor_len in [256, 512]:
            out = bytes(cdata[i] ^ k[i % len(k[:xor_len])] for i in range(4096))
            stp, ret = find_valid_arm64(out)
            e = entropy(out[:512])
            if stp > 0 or e < 6.0:
                print(f'  [XOR]  sbox+0x{koff2:x}_{xor_len}B ent={e:.2f} stp={stp} <<<')
    
    # 变体3: Build S-box from scratch (0-255) then KSA with key
    S_std = list(range(256))
    for koff3 in [0x13068, 0x13000]:
        for klen3 in [16, 32]:
            key3 = list(dx[koff3:koff3+klen3])
            if len(key3) < klen3: continue
            S3 = S_std[:]
            j = 0
            for i in range(256):
                j = (j + S3[i] + key3[i % len(key3)]) & 0xFF
                S3[i], S3[j] = S3[j], S3[i]
            i = j = 0
            out = bytearray()
            for byte in cdata[:4096]:
                i = (i + 1) & 0xFF
                j = (j + S3[i]) & 0xFF
                S3[i], S3[j] = S3[j], S3[i]
                k = S3[(S3[i] + S3[j]) & 0xFF]
                out.append(byte ^ k)
            stp, ret = find_valid_arm64(out)
            if stp > 0:
                print(f'  [STD]  key@0x{koff3:x}_{klen3}B ent={entropy(out[:512]):.2f} stp={stp} <<<')

print('\n=== 如果什么都没出来：尝试简单单字节 XOR ===')
for cname, cdata in candidates.items():
    if len(cdata) < 256: continue
    for x in range(256):
        out = bytes(b ^ x for b in cdata[:512])
        e = entropy(out)
        if e < 4.0:
            print(f'  {cname} XOR 0x{x:02x}: ent={e:.2f}')
    break  # 只试第一个