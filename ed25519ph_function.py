p = 2**255 - 19
a = -1
d = -121665 * pow(121666, p - 2, p) % p
l = 2**252 + 27742317777372353535851937790883648493


def base_point() -> tuple:
    By = (4 * pow(5, p - 2, p)) % p
    _u = (By * By - 1) % p
    _v = (d * By * By + 1) % p
    _v3 = pow(_v, 3, p)
    _v7 = pow(_v, 7, p)
    Bx = (_u * _v3 * pow(_u * _v7, (p - 5) // 8, p)) % p

    if (_v * Bx * Bx) % p == (-_u) % p:
        Bx = (Bx * pow(2, (p - 1) // 4, p)) % p
    if Bx & 1:
        Bx = p - Bx

    assert ((p - 1) * Bx * Bx + By * By) % p == (1 + d * Bx * Bx * By * By) % p, \
        "Titik basis tidak valid di kurva Edwards25519!"

    return (Bx % p, By % p, 1, (Bx * By) % p)

BASE_POINT = base_point()


def point_identity():
    return (0, 1, 1, 0)


def affine_to_extended(x, y: int) -> tuple:
    return (x % p, y % p, 1, (x * y) % p)


def extended_to_affine(P: tuple) -> tuple:
    X, Y, Z, T = P
    Zi = pow(Z, p - 2, p)
    return (X * Zi % p, Y * Zi % p)


def point_add(P, Q: tuple) -> tuple:
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q

    A = ((Y1 - X1) * (Y2 - X2)) % p
    B = ((Y1 + X1) * (Y2 + X2)) % p
    C = (T1 * 2 * d * T2) % p
    D = (Z1 * 2 * Z2) % p

    E = (B - A) % p
    F = (D - C) % p
    G = (D + C) % p
    H = (B + A) % p

    X3 = (E * F) % p
    Y3 = (G * H) % p
    T3 = (E * H) % p
    Z3 = (F * G) % p

    return (X3, Y3, Z3, T3)


def point_double(P: tuple) -> tuple:
    X1, Y1, Z1, T1 = P

    A = (X1 * X1) % p
    B = (Y1 * Y1) % p
    C = (2 * Z1 * Z1) % p
    D = (A + B) % p
    E = (D - (X1 + Y1) * (X1 + Y1)) % p
    F = (A - B) % p
    G = (C + F) % p

    X2 = (E * G) % p
    Y2 = (F * D) % p
    T2 = (E * D) % p
    Z2 = (G * F) % p

    return (X2, Y2, Z2, T2)


def scalar_mult(k: int, P: tuple) -> tuple:
    k = k % l
    result = point_identity()  

    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1

    return result


def encode_point(P: tuple) -> bytes:
    x, y = extended_to_affine(P)
    encoded = bytearray(y.to_bytes(32, 'little'))
    if x & 1:
        encoded[31] |= 0x80
    return bytes(encoded)


def decode_point(b: bytes) -> tuple:
    if len(b) != 32:
        raise ValueError("Panjang byte titik harus 32")

    b = bytearray(b)
    sign_x = (b[31] & 0x80) >> 7
    b[31] &= 0x7F
    y = int.from_bytes(b, 'little')

    if y >= p:
        raise ValueError("Koordinat y melebihi modulus p")

    y2 = (y * y) % p
    u = (y2 - 1) % p
    v = (d * y2 + 1) % p  

    x = (pow(u, 3) * pow(v, 1) * pow(pow(u, 5) * pow(v, 3), (p - 5) // 8, p)) % p
    v3 = pow(v, 3, p)
    v7 = pow(v, 7, p)
    x = (u * v3 * pow(u * v7, (p - 5) // 8, p)) % p

    vx2 = (v * x * x) % p
    if vx2 == u % p:
        pass  
    elif vx2 == (-u) % p:
        x = (x * pow(2, (p - 1) // 4, p)) % p
    else:
        raise ValueError("Tidak ada akar kuadrat: titik tidak valid di kurva")

    if x == 0 and sign_x == 1:
        raise ValueError("x=0 tapi sign bit x=1, titik tidak valid")
    if (x & 1) != sign_x:
        x = p - x

    if (a * x * x + y * y) % p != (1 + d * x * x * y * y) % p:
        raise ValueError("Titik terverifikasi tidak memenuhi persamaan kurva")

    return (x % p, y % p, 1, (x * y) % p)


def scalar_clamping(h32: bytes) -> int:
    h = bytearray(h32)
    h[0] &= 248   
    h[31] &= 127  
    h[31] |= 64    
    return int.from_bytes(h, 'little')


def dom2(phflag: int, ctx: bytes) -> bytes:
    if len(ctx) > 255:
        raise ValueError(f"Konteks terlalu panjang: {len(ctx)} byte (maks 255)")
    prefix = b"SigEd25519 no Ed25519 collisions"
    return prefix + bytes([phflag]) + bytes([len(ctx)]) + ctx