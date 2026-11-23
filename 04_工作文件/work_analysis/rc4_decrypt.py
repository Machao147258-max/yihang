#!/usr/bin/env python3
"""实现 libcorejni 的完整解密算法 (RC4 变体)"""
import collections, math

ct = open('C:/Users/dev/Desktop/样本/libs_arm64/libKbCrypter.so','rb').read()
dx = open('C:/Users/dev/Desktop/样本/libs_arm64/libcorejni.so','rb').read()

# 从 0x13000 取 256 字节状态表
S_init = list(dx[0x13000:0x13100])

# 从 0x13068 取 key（32 字节密钥材料）
KEY = list(dx[0x13068:0x13098])
key_len = len(KEY)

def decrypt_block(data, S, key):
    """自定义 RC4 变体解密一个块"""
    # KSA 变体: 用 0x13000 的 S-box + key
    S = S[:]  # 拷贝
    j = 0
    n = len(S)
    for i in range(n):
        j = (j + S[i] + key[i % key_len]) & 0xFF
        S[i], S[j] = S[j], S[i]
    
    # PRGA 变体
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        out.append(byte ^ k)
    return bytes(out)

# 解密密文段
ciphertext = ct[0xc000:0x9c000]
print(f'Decrypting {len(ciphertext)} bytes...')

# 分 16KB 块解密
result = bytearray()
for off in range(0, len(ciphertext), 4096):
    chunk = ciphertext[off:off+4096]
    dec = decrypt_block(chunk, S_init, KEY)
    result.extend(dec)

# 验证
e = -sum((v/len(result[:4096]))*math.log2(v/len(result[:4096])) for v in collections.Counter(result[:4096]).values())
stp = result[:4096].count(b'\xfd\x7b')
print(f'entropy: {e:.2f}, stp count: {stp}')
if stp > 3 or e < 5.0:
    print('[+] SUCCESS! Saving...')
    open('C:/Users/dev/Desktop/work_analysis/dumps/decrypted_skb.bin','wb').write(result)
else:
    print('[-] Still no valid code, trying variations...')
    # 试不同的 KSA 排列（0x13000 表可能不是初始 S-box 而是置换表）
    S2 = list(range(256))
    for i in range(256):
        S2[i] = S_init[S2[i]] if S_init[i] < 256 else S2[i]
    dec2 = decrypt_block(ciphertext[:4096], S2, KEY)
    e2 = -sum((v/len(dec2))*math.log2(v/len(dec2)) for v in collections.Counter(dec2).values())
    stp2 = dec2[:4096].count(b'\xfd\x7b')
    print(f'  variant2: ent={e2:.2f} stp={stp2}')