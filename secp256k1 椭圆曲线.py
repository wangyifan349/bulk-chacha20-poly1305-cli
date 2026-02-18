import secrets
import hashlib
from bech32 import encode, convertbits
from typing import Optional, Tuple

# secp256k1 curve parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
O: Optional[Tuple[int, int]] = None  # Point at infinity

def inv_mod(k: int, p: int) -> int:
    if k == 0:
        raise ZeroDivisionError('division by zero')
    return pow(k, p-2, p)

def point_add(P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
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
    x, y = P
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

def pubkey_compressed(P: Tuple[int, int]) -> bytes:
    x, y = P
    return (b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(32, 'big')

def hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha).digest()

def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    witprog5 = convertbits(witprog, 8, 5, True)
    return encode(hrp, [witver] + witprog5)

def bip84_address(P: Tuple[int, int], hrp: str = "bc") -> str:
    pk_hash = hash160(pubkey_compressed(P))
    return bech32_encode(hrp, 0, pk_hash)

def base58_encode(data: bytes) -> str:
    # Base58 character set
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    enc = ''
    while num > 0:
        num, rem = divmod(num, 58)
        enc = alphabet[rem] + enc
    # Add '1' for each leading 0 byte
    pad = 0
    for c in data:
        if c == 0:
            pad += 1
        else:
            break
    return '1' * pad + enc

def wif_encode(priv: int, compressed: bool = True, testnet: bool = False) -> str:
    # Private key to Wallet Import Format (WIF)
    prefix = b'\x80' if not testnet else b'\xef'
    priv_bytes = priv.to_bytes(32, 'big')
    if compressed:
        payload = prefix + priv_bytes + b'\x01'
    else:
        payload = prefix + priv_bytes
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58_encode(payload + checksum)

# ======== Secure private key generation ========
def gen_priv_key() -> int:
    while True:
        priv = secrets.randbits(256)
        if 1 <= priv < n:
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
