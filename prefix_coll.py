# Find a SHA2 224 collision where the first 'length' bytes of the hash tag match 
# but the two byte objects are different.

# GW

import argparse
from cryptography.hazmat.primitives import hashes
import os


def string_to_bytes(string):
    return string.encode('utf-8')


def hash_bytes(input):
    # https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes.html
    digest = hashes.Hash(hashes.SHA224())
    digest.update(input)
    return digest.finalize()


def compare_bytes(A, B, length):
    if (len(A) < length):
        return False
    if (len(B) < length):
        return False
    prefix_A = A[0:length]
    prefix_B = B[0:length]
    if prefix_A == prefix_B:
        return True
    else:
        return False


def find_collision(length):
    size = 225
    maxhashes = 10*(int(2 ** (length * 8 / 2)) + 1)

    # hash then check if we already have an entry for 'length' bytes of that hash
    hashtable = {}
    for x in range(maxhashes):
        bytes_temp1 = string_to_bytes((os.urandom(size)).hex())
        hash_of_temp1 = hash_bytes(bytes_temp1)
        if hashtable.get(hash_of_temp1[0:length]) != None:
            if hashtable.get(hash_of_temp1[0:length]) != bytes_temp1:
                return (hashtable.get(hash_of_temp1[0:length]), bytes_temp1)
        else:
            hashtable[hash_of_temp1[0:length]] = bytes_temp1



if __name__ == '__main__':

    cmdline = argparse.ArgumentParser(description='Find two hash collisions, within the given length.')
    cmdline.add_argument('--length', metavar='INT', type=int, default=5,
                         help='The first X characters of the hashes that must match.')

    args = cmdline.parse_args()

    if args.length < 1:
        print(f"ERROR! Please supply a length that's greater than 0, not '{args.length}'.")

    ret = find_collision(args.length)

    if ret is None:
        print(f"I'm sorry, I couldn't find a collision for length {args.length}. Please try a shorter value.")
    elif (type(ret) is tuple) and (len(ret) == 2):
        print(f"I found a collision where the first {args.length} of the hash match!")
        A, B = ret
        print(f"{hash_bytes(A).hex()} = HASH({A})")
        print(f"{hash_bytes(B).hex()} = HASH({B})")

        
