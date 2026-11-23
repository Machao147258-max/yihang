#!/usr/bin/env python3
"""libcorejni 0x1184 函数 ARM64 → Python 逐指令翻译"""
import struct, collections, math

d = open('C:/Users/dev/Desktop/样本/libs_arm64/libcorejni.so','rb').read()
skb_ct = open('C:/Users/dev/Desktop/样本/libs_arm64/libKbCrypter.so','rb').read()[0xc000:0x9c000]

KEY = list(d[0x13068:0x13078])  # 16B

def dec_loop(data, size):
    """逐指令翻译 0x12b0-0x13cc"""
    sp = [0] * 0x200  # 栈模拟（大了点）
    S_base = 0x28     # S-box 从 sp+0x28 开始
    
    # 初始化 S = [0..255] (0x12b0-0x12cc)
    x4 = S_base
    x1 = 0
    for _ in range(256):
        sp[x4 + x1] = x1 & 0xFF  # strb w1, [x4, x1]
        x1 += 1
    
    # KSA (0x12d0-0x132c)
    x9_0x13068_base = 0  # key base (逻辑地址)
    x5 = x4            # x5 = &S[0]
    x8 = x4 + 0xFF     # x8 = &S[255]
    w1 = 1             # key index
    # 初始: w6 = S[0], w2 = key[0] + S[0]
    w6 = sp[x4] & 0xFF  # ldrb w6, [x4]
    w2 = KEY[0] + w6   # ldrb w2, [x2, #0x68]; add w2, w2, w6
    w2 = w2 & 0xFF     # and w2, w2, #0xff
    
    while True:
        # 0x131c
        w3 = w2        # mov w3, w2
        # cmp x5, x8  # check if loop done
        # 0x1320: ldrb w7, [x4, x3]
        idx_i = x5 - x4 if x5 >= x4 else 0
        idx_j = w3
        w7 = sp[x4 + idx_j] & 0xFF
        # 0x1324: strb w7, [x5] - S[i] = S[j]
        sp[x5] = w7 & 0xFF
        # 0x1328: strb w6, [x4, x3] - S[j] = old S[i]
        sp[x4 + idx_j] = w6 & 0xFF
        
        # 0x132c: b.ne 0x12f8
        if x5 == x8:
            break
        
        # 0x12f8: ldrb w6, [x5, #1]!  (pre-index)
        x5 += 1
        w6 = sp[x5] & 0xFF
        
        # 0x12fc: ldrb w3, [x9, w1, sxtw]
        w3 = KEY[w1] & 0xFF
        
        # 0x1300: add w1, w1, #1
        w1 += 1
        
        # 0x1304: add w2, w6, w2
        w2 = (w6 + w2) & 0xFFFFFFFF
        
        # 0x1308: cmp w1, #0x10
        # 0x130c: add w2, w2, w3
        w2 = w2 + w3
        
        # 0x1310: csel w1, w1, wzr, lt
        if w1 >= 16:
            w1 = 0
        
        # 0x1314: and w2, w2, #0xff
        w2 = w2 & 0xFF
    
    # PRGA (0x1330-0x13cc)
    # cbz x12, #0x13e8  (no x12 in my sim, skip)
    # mov w3, #0; mov w2, w3; mov w1, w3
    w3_new = 0
    w2_new = 0
    w1_new = 0
    
    ii = w1_new
    jj = w2_new
    
    out = bytearray()
    for byte_idx in range(size):
        # 0x137c: add w1, w1, #1
        ii = (ii + 1) & 0xFF
        
        # 0x1380: ldrb w6, [x5], #1  (read data byte, x5++)
        if byte_idx < len(data):
            w6 = data[byte_idx]
        else:
            w6 = 0
        
        # 0x1384: and w7, w1, #0xff
        w7 = ii
        
        # 0x138c: mov x1, x7
        # 0x1394: ldrb w3, [x4, x7] - S[i]
        w3 = sp[x4 + w7] & 0xFF
        
        # 0x1398: add w2, w2, w3 - j += S[i]
        jj = (jj + w3) & 0xFF
        
        # 0x139c: and w8, w2, #0xff
        w8 = jj
        
        # 0x13a0: mov x2, x8
        # 0x13a4: ldrb w9, [x4, x8] - S[j]
        w9 = sp[x4 + w8] & 0xFF
        
        # 0x13a8: strb w9, [x4, x7] - S[i] = S[j]
        sp[x4 + w7] = w9 & 0xFF
        
        # 0x13ac: strb w3, [x4, x8] - S[j] = old S[i]
        sp[x4 + w8] = w3 & 0xFF
        
        # 0x13b0: ldrb w7, [x4, x7] - w7 = S[i] (now contains old S[j])
        w7_new = sp[x4 + w7] & 0xFF
        
        # 0x13b4: add w3, w7, w3 - w3 = S[i] + S[j]
        w3_combined = (w7_new + (sp[x4 + w8] & 0xFF)) # wait, this is wrong
        # Actually w3 was old S[i], and w7_new is old S[j] (now at S[i])
        # w3 = w7_new + w3 = S[i] + S[j]
        w3_val = (w7_new + w3) & 0xFF
        
        # 0x13b8: uxtb w3, w3
        w3_val = w3_val & 0xFF
        
        # 0x13bc: ldrb w3, [x4, x3]
        k = sp[x4 + w3_val] & 0xFF
        
        # 0x13c0: eor w6, w3, w6
        dec = (k ^ w6) & 0xFF
        
        # 0x13c4: sturb w6, [x5, #-1]
        out.append(dec)
    
    return bytes(out)

# 解密密文
print('Decrypting KbcrypterCrypter ciphertext...')
result = dec_loop(skb_ct, len(skb_ct))

# 验证
e = -sum((v/len(result[:4096]))*math.log2(v/len(result[:4096])) for v in collections.Counter(result[:4096]).values())
stp = result[:4096].count(b'\xfd\x7b')
print(f'entropy={e:.2f} stp={stp}')
if stp > 3 or e < 6.0:
    print('SUCCESS! Saving...')
    open('C:/Users/dev/Desktop/work_analysis/decrypted_skb.so', 'wb').write(result)
else:
    print('Still not correct. First 64 bytes:', result[:64].hex())