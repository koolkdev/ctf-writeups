# Based on the MD5 implementation:
# https://github.com/timvandermeij/md5.py/blob/master/md5.py

from z3 import *
import struct
from math import (
    floor,
    sin,
)

# Define the four auxiliary functions that produce one 32-bit word.
F = lambda x, y, z: (x & y) | (~x & z)
G = lambda x, y, z: (x & z) | (y & ~z)
H = lambda x, y, z: x ^ y ^ z
I = lambda x, y, z: y ^ (x | ~z)

# Define the left rotation function, which rotates `x` left `n` bits.
rotate_left = lambda x, n: (x << n) | LShR(x, (32 - n))
#rotate_left = lambda x, n: (x << n) | (x >> (32 - n))

# Define a function for modular addition.
modular_add = lambda a, b: (a + b) & 0xffffffff

# Compute the T table from the sine function. Note that the
# RFC starts at index 1, but we start at index 0.
T = [floor(pow(2, 32) * abs(sin(i + 1))) for i in range(64)]

def do_md5_round(i, A, B, C, D, X):
    if 0 <= i <= 15:
        k = i
        s = [7, 12, 17, 22]
        temp = F(B, C, D)
    elif 16 <= i <= 31:
        k = ((5 * i) + 1) % 16
        s = [5, 9, 14, 20]
        temp = G(B, C, D)
    elif 32 <= i <= 47:
        k = ((3 * i) + 5) % 16
        s = [4, 11, 16, 23]
        temp = H(B, C, D)
    elif 48 <= i <= 63:
        k = (7 * i) % 16
        s = [6, 10, 15, 21]
        temp = I(B, C, D)

    # The MD5 algorithm uses modular addition. Note that we need a
    # temporary variable here. If we would put the result in `A`, then
    # the expression `A = D` below would overwrite it. We also cannot
    # move `A = D` lower because the original `D` would already have
    # been overwritten by the `D = C` expression.
    temp = modular_add(temp, X[k])
    temp = modular_add(temp, T[i])
    temp = modular_add(temp, A)
    temp = rotate_left(temp, s[i % 4])
    temp = modular_add(temp, B)

    # Swap the registers for the next operation.
    A = D
    D = C
    C = B
    B = temp
    return (A, B, C, D)

states = [941, 339, 875, 28, 38, 135, 809, 706, 183, 825, 130, 465, 629, 174, 414, 647, 177, 476, 581, 853, 921, 115, 316, 815, 256, 474, 706, 743, 970, 909, 424, 936, 812, 260, 996, 1, 864, 744, 713, 390, 603, 198, 357, 779, 715, 679, 436, 867, 345, 494, 559, 1023, 795, 716, 476, 186, 284, 879, 893, 374, 47, 1009, 284, 51]

buff = [BitVec("x%d" % i, 32) for i in range(8)]
padded_buffer = [buff[0], buff[1], buff[2], buff[3], buff[4], buff[5], buff[6], 0x800000 | buff[7], 0, 0, 0, 0, 0, 0, 0xF0, 0]

s = Solver()

# We have 30 ascii chars
for i in range(7):
    s.add(buff[i] & 0x80808080 == 0)
s.add(buff[7] & 0xffff8080 == 0)

A, B, C, D = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

# 25 rounds are enough
for i in range(25):
    A, B, C, D = do_md5_round(i, A, B, C, D, padded_buffer)
    new_state = [BitVec("s_%d_%d" % (i, j), 32) for j in range(4)]
    s.add(B & 0x3ff == states[i])
    
    s.add(new_state[0] == A)
    s.add(new_state[1] == B)
    s.add(new_state[2] == C)
    s.add(new_state[3] == D)
    A, B, C, D = new_state

s.check()
print("hxp{" + b"".join(struct.pack("<I", s.model()[x].as_long()) for x in buff)[:-2].decode() + "}")

