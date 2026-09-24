import os
import hashlib
from ed25519ph_function import (
    scalar_clamping, 
    scalar_mult, 
    encode_point, 
    BASE_POINT
)


def generate_keypair():
    seed = os.urandom(32)
    h = hashlib.sha512(seed).digest() 
    s = scalar_clamping(h[:32])  
    prefix = h[32:]
    public_key = encode_point(scalar_mult(s, BASE_POINT))

    return {
        'seed_hex': seed.hex(),
        'privkey_hex': (seed + public_key).hex(),
        'pubkey_hex': public_key.hex(),
        'scalar_s': s,
        'prefix': prefix.hex()
    }


def load_keypair_from_seed(seed_hex):
    try:
        seed = bytes.fromhex(seed_hex)
    except ValueError:
        raise ValueError("Seed harus berupa hex string valid")

    if len(seed) != 32:
        raise ValueError(f"Seed harus 32 byte, didapat {len(seed)} byte")

    h = hashlib.sha512(seed).digest()
    s = scalar_clamping(h[:32])
    prefix = h[32:]

    public_key = encode_point(scalar_mult(s, BASE_POINT))

    return {
        'seed_hex': seed.hex(),
        'privkey_hex': (seed + public_key).hex(),
        'pubkey_hex': public_key.hex(),
        'scalar_s': s,
        'prefix': prefix.hex()
    }


if __name__ == '__main__':
    print("=== Tes Pembangkitan Kunci Ed25519ph ===")
    keypair = generate_keypair()
    print(f"Seed      : {keypair['seed_hex']}")
    print(f"Kunci Publik: {keypair['pubkey_hex']}")