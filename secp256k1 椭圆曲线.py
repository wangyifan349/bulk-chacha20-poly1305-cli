import os
import hashlib
from typing import Optional, Tuple
from bech32 import encode, convertbits  # pip install bech32

# secp256k1 椭圆曲线参数
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

O: Optional[Tuple[int, int]] = None  # 无穷点

def inv_mod(k: int, p: int) -> int:
    # 计算 k 在模 p 下的逆元
    if k == 0:
        raise ZeroDivisionError('division by zero')
    return pow(k, p-2, p)

def point_add(P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    # 椭圆曲线加法
    if P is None: return Q
    if Q is None: return P
    (x1, y1) = P
    (x2, y2) = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return O
    if P != Q:
        lam = ((y2 - y1) * inv_mod(x2 - x1, p)) % p
    else:
        if y1 == 0:
            return O
        lam = ((3 * x1 * x1 + a) * inv_mod(2 * y1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mul(k: int, P: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    # 椭圆曲线标量乘法（双倍加法算法）
    if k % n == 0 or P is None:
        return O
    if k < 0:
        return scalar_mul(-k, (P[0], (-P[1]) % p))
    R = O
    Q = P
    while k:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

def pubkey_uncompressed(P: Tuple[int, int]) -> bytes:
    # 公钥非压缩格式（65字节）
    x, y = P
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def pubkey_compressed(P: Tuple[int, int]) -> bytes:
    # 公钥压缩格式（33字节）
    x, y = P
    return (b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(32, 'big')

def hash160(data: bytes) -> bytes:
    # RIPEMD160(SHA256(data))
    sha = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha).digest()

def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    # BIP84 bech32编码
    witprog5 = convertbits(witprog, 8, 5, True)
    return encode(hrp, [witver] + witprog5)

def bip84_address(P: Tuple[int, int], hrp: str = "bc") -> str:
    # 生成 BIP84(bech32) 地址
    pk_hash = hash160(pubkey_compressed(P))
    return bech32_encode(hrp, 0, pk_hash)

# ======== 生成密钥与地址 ========

priv = int.from_bytes(os.urandom(32), 'big') % n
if priv == 0:
    priv = 1

pub = scalar_mul(priv, G)
print("私钥(hex): 0x%x" % priv)
print("公钥点:\nx=0x%064x\ny=0x%064x" % (pub[0], pub[1]))

uncompressed = pubkey_uncompressed(pub)
compressed = pubkey_compressed(pub)
print("非压缩公钥(hex):", uncompressed.hex())
print("压缩公钥(hex):", compressed.hex())

bip84_addr = bip84_address(pub, hrp='bc')
print("BIP84(bech32)地址:", bip84_addr)
