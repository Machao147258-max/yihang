#!/usr/bin/env python3
"""
Shell so 解密尝试
从 libcorejni.so 提取密钥，尝试 AES 解密 libKbCrypter.so 的密文段
"""

import struct
import hashlib
import re
from Crypto.Cipher import AES
from collections import Counter

BASE = 'C:/Users/dev/Desktop/样本/libs_arm64/'

def load_so(name):
    return open(BASE + name, 'rb').read()

def extract_keys(data):
    """从数据区提取所有 16/32 字节候选密钥"""
    keys = []
    # 提取所有 16 字节连续非零块（步进 1 字节）
    for off in range(0, len(data) - 15):
        for sz in [16, 24, 32]:
            blk = data[off:off+sz]
            if all(32 <= b < 127 for b in blk) and len(set(blk)) > 10:
                keys.append((off, 'ascii', blk))
            elif all(b != 0 for b in blk) and len(set(blk)) > 8:
                # 高熵字节块
                ent = -sum((v/sz)*__import__('math').log2(v/sz) for v in Counter(blk).values())
                if ent > 6.5:
                    keys.append((off, 'high', blk))
    return keys

def try_decrypt(ciphertext, key, iv, label):
    """尝试 AES-CBC 解密"""
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain = cipher.decrypt(ciphertext[:len(ciphertext)//16*16])
        # 验证：检查解密后的数据是否有有效 ARM64 指令模式
        stp_cnt = plain[:4096].count(b'\xfd\x7b')  # stp x29, x30 的常见编码
        ent = -sum((v/4096)*__import__('math').log2(v/4096) 
                   for v in Counter(plain[:4096]).values())
        print(f'  {label}: stp_count={stp_cnt} entropy={ent:.2f}' 
              + (' <<< GOOD' if stp_cnt > 5 and ent < 6.5 else ''))
    except Exception as e:
        print(f'  {label}: error {e}')

if __name__ == '__main__':
    skb = load_so('libKbCrypter.so')
    corejni = load_so('libcorejni.so')
    
    # 密文段: 从 0xc000 到 0x9c000 (根据熵图)
    ct = skb[0xc000:0x9c000]
    print(f'KbcrypterCrypter: {len(skb)}B, ciphertext: {len(ct)}B @ 0xc000')
    
    # 候选密钥来源 1: libcorejni 的数据区
    print('\n=== 提取候选密钥 ===')
    keys = extract_keys(corejni[0x13000:0x14000])
    print(f'找到 {len(keys)} 个候选密钥')
    
    print('\n=== AES-128-CBC 解密测试 ===')
    iv = b'\x00' * 16  # 初始尝试用全零 IV
    
    # 尝试不同密钥
    for off, typ, key in keys[:20]:
        if len(key) >= 16:
            try_decrypt(ct, key[:16], iv, f'0x{off:x} {typ[:5]} key={key[:16].hex()[:20]}...')
    
    # 也尝试 libcorejni 整个 so 的 md5 作为密钥
    md5k = hashlib.md5(corejni).digest()[:16]
    try_decrypt(ct, md5k, iv, 'md5(corejni)')
    
    # 尝试从静态 dex 提取特征密钥
    static_dex = open('C:/Users/dev/Desktop/样本/classes.dex', 'rb').read()
    md5k2 = hashlib.md5(static_dex).digest()[:16]
    try_decrypt(ct, md5k2, iv, 'md5(classes.dex)')
    
    print('\n=== 如果上面都没有 "GOOD" 标记, 需要其他 IV ===')
    print('IVAES-128-CBC IV 尝试: key1 + iv=key, key=iv')
    if len(keys) > 1:
        key1 = keys[0][2][:16]
        if len(key1) == 16:
            try_decrypt(ct, key1, key1, 'key=iv=key1')