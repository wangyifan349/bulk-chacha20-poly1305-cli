"""
详细逻辑清单
1. 设定 secp256k1 椭圆曲线参数（包括素数p，参数a、b，基点G，阶n）
2. 定义椭圆曲线点的加法（point_add）和标量乘法（scalar_mul），实现基本的椭圆曲线数学运算
3. 采用 secrets.randbits(256) 生成高熵随机数，循环确保私钥落在合法区间 [1, n-1] 内部，避免私钥非均匀分布
4. 用上述私钥进行椭圆曲线标量乘法，得到唯一对应公钥点 (x, y)
5. 分别实现公钥的非压缩格式（0x04前缀 + x坐标 + y坐标）和压缩格式（0x02/0x03前缀 + x坐标编码）
6. 计算 hash160（即 RIPEMD160(SHA256(x)）的公钥哈希，为生成地址做准备
7. 实现 BIP84 (SegWit/bech32，原生隔离见证地址) 地址格式的编码：对 hash160(压缩公钥) 做 bech32编码形成标准BIP84地址
8. 实现私钥的WIF（Wallet Import Format）编码，包括前缀、是否压缩公钥标志、双SHA256校验和、Base58编码，得到用于钱包导入的人类友好私钥格式
9. 程序主流程：依次展示私钥（16进制，WIF），公钥坐标、压缩/非压缩公钥(hex形式)，以及最终BIP84地址
程序概要说明
本程序完成了从高安全性随机生成私钥，到椭圆曲线加解密计算公钥，再到各种标准格式（非压缩/压缩公钥、WIF私钥、隔离见证bech32地址）的比特币密钥和地址相关全部流程，且全过程基于底层数学，逻辑透明，安全合规，适合学习、分析、或在定制钱包开发中参考使用。

免责声明
本程序仅用于教育学习和技术研究用途，不建议用于存储、转移真实比特币等实际金融场景。作者不对因本程序生成密钥或地址可能带来的任何资产损失、隐私泄露或法律风险承担任何责任。
请勿将资金存放在通过本程序生成的私钥地址和收款地址中。
如果您有实际比特币资产管理需求，强烈建议使用业界知名、口碑良好的开源钱包，如 Electrum 比特币钱包（https://electrum.org/）。Electrum 钱包经过多年社区审计和实战验证，易用且安全，支持多种地址和恢复方式，适用于个人桌面和移动端环境。 Electrum 可为用户自动生成高强度助记词和密钥，更安全地管理您的比特币资产。
"""
import secrets
import hashlib
from bech32 import encode, convertbits
from typing import Optional, Tuple

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
    if k == 0:
        raise ZeroDivisionError('division by zero')
    return pow(k, p-2, p)

def point_add(P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
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
    if k % n == 0 or P is None:
        return O
    if k < 0:
        x, y = P
        return scalar_mul(-k, (x, (-y) % p))
    R = O
    Q = P
    while k:
        if k & 1:
            R = point_add(R, Q)
        Q = point_add(Q, Q)
        k >>= 1
    return R

def pubkey_uncompressed(P: Tuple[int, int]) -> bytes:
    x, y = P
    result = b'\x04'
    result = result + x.to_bytes(32, 'big')
    result = result + y.to_bytes(32, 'big')
    return result

def pubkey_compressed(P: Tuple[int, int]) -> bytes:
    x, y = P
    prefix = b'\x02'
    if y % 2 != 0:
        prefix = b'\x03'
    result = prefix + x.to_bytes(32, 'big')
    return result

def hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    rmd = hashlib.new('ripemd160')
    rmd.update(sha)
    return rmd.digest()

def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    witprog8 = []
    for b in witprog:
        witprog8.append(b)
    witprog5 = convertbits(witprog8, 8, 5, True)
    values = [witver]
    for v in witprog5:
        values.append(v)
    return encode(hrp, values)

def bip84_address(P: Tuple[int, int], hrp: str = "bc") -> str:
    pk_hash = hash160(pubkey_compressed(P))
    return bech32_encode(hrp, 0, pk_hash)

def base58_encode(data: bytes) -> str:
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    enc = ''
    while num > 0:
        num, rem = divmod(num, 58)
        enc = alphabet[rem] + enc
    pad = 0
    for c in data:
        if c == 0:
            pad += 1
        else:
            break
    result = ''
    for i in range(pad):
        result = result + '1'
    result = result + enc
    return result

def wif_encode(priv: int, compressed: bool = True, testnet: bool = False) -> str:
    prefix = b'\x80'
    if testnet:
        prefix = b'\xef'
    priv_bytes = priv.to_bytes(32, 'big')
    if compressed:
        payload = prefix + priv_bytes + b'\x01'
    else:
        payload = prefix + priv_bytes
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    result = payload + checksum
    return base58_encode(result)

def gen_priv_key() -> int:
    while True:
        priv = secrets.randbits(256)
        if priv >= 1 and priv < n:
            return priv

priv = gen_priv_key()
pub = scalar_mul(priv, G)

print("私钥(hex): 0x%x" % priv)
print("私钥WIF (压缩):", wif_encode(priv, compressed=True, testnet=False))
print("公钥点:\nx=0x%064x\ny=0x%064x" % (pub[0], pub[1]))
uncompressed = pubkey_uncompressed(pub)
compressed = pubkey_compressed(pub)
print("非压缩公钥(hex):", uncompressed.hex())
print("压缩公钥(hex):", compressed.hex())
bip84_addr = bip84_address(pub, hrp='bc')
print("BIP84(bech32)地址:", bip84_addr)
