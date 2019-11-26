import random


def gcd(a, b):
    """
    Euklideszi algoritmus
    """
    while b != 0:
        a, b = b, a % b
    return a


def kibov_euklidesz(phi, a):
    """
    Kibővített Euklideszi alg.
    """
    base_a, base_phi = a, phi
    x0, x1, y0, y1, s = 1, 0, 0, 1, 1
    while a != 0:
        # print("Start of Cycle!\n")
        r, q = phi % a, int(phi / a)
        # print(f"r: {r}; q: {q}")
        phi, a = a, r
        # print(f"phi: {phi}; a: {a}")
        x, y = x1, y1
        # print(f"x: {x}; y: {y}")
        x1, y1 = q * x1 + x0, q * y1 + y0
        # print(f"x1: {x1}; y1: {y1}")
        x0, y0 = x, y
        # print(f"x0: {x0}; y0: {y0}")
        s = -s
        # print(f"s: {s}")
        # print("\n End of Cycle!")
    x, y = s * x0, -y0
    x = x % base_a
    y = y % base_phi
    #print(f"\n final - x: {x}; y: {y}")
    return x, y


def is_prime_mr(n):
    """
    Miller-Rabin primality test.

    A return value of False means n is certainly not prime. A return value of
    True means n is very likely a prime.
    """
    if n != int(n):
        return False
    n = int(n)
    if n == 0 or n == 1 or n == 4 or n == 6 or n == 8 or n == 9:
        return False

    if n == 2 or n == 3 or n == 5 or n == 7:
        return True
    s = 0
    d = n - 1
    while d % 2 == 0:
        d = int(d/2)
        s += 1
    assert (2 ** s * d == n - 1)

    def trial_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2 ** i * d, n) == n - 1:
                return False
        return True

    for i in range(8):  # number of trials
        a = random.randrange(2, n)
        if trial_composite(a):
            return False

    return True


def chinese_remainder(d, c):
    m1, m2 = q, p
    x1, y1 = kibov_euklidesz(q, p)
    x2, y2 = kibov_euklidesz(p, q)
    c1 = pow((c % p), (d % (p-1)), p)
    c2 = pow((c % q), (d % (q-1)), q)
    return (c1*x1*m1 + c2*x2*m2) % (p * q)


def generate_keypair(p, q):
    if not (is_prime_mr(p) and is_prime_mr(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    x, y = kibov_euklidesz(e, phi)
    d = x % phi
    return (e, n), (d, n)


def encrypt(pk, plaintext):
    key, n = pk
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher


def decrypt(pk, ciphertext):
    global p, q
    key, n = pk
    plain = [chr(chinese_remainder(key, char)) for char in ciphertext]
    return ''.join(plain)


if __name__ == '__main__':
    print("RSA Encrypter/ Decrypter")
    p = int(input("Enter a prime number (17, 19, 23, etc): "))
    q = int(input("Enter another prime number (Not one you entered above): "))
    print("Generating your public/private keypairs now . . .")
    public, private = generate_keypair(p, q)
    print("Your public key is ", public, " and your private key is ", private)
    message = input("Enter a message to encrypt: ")
    encrypted_msg = encrypt(private, message)
    print("Your encrypted message is:")
    print(''.join(map(lambda x: str(x), encrypted_msg)))
    print("Decrypting message. . .")
    print("Your message is:")
    print(decrypt(public, encrypted_msg))
