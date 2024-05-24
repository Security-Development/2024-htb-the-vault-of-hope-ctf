from pwn import *
from Crypto.Util.number import long_to_bytes as l2b
from multiprocessing import Pool, Manager

context.log_level = 'debug'

def solve(index, flag_list):
    try:
        p = remote("83.136.253.219", 49862)
        data = []
        for _ in range(35):
            p.recvuntil(b"Specify the index of the bit you want to get an encryption for : ")
            p.sendline(str(index).encode())
            p.recvuntil(b"A = ")
            A = int(p.recvline().strip())
            p.recvuntil(b"b = ")
            b = int(p.recvline().strip())
            print("A : %d" % A)
            print("b : %d" % b)
            data.append(b)
            print("index : %d, flag : %s, %d" % (index, flag_list, len(flag_list)))

        if any(x < -5 for x in data):
            print("1")
            flag_list[index] = '1'
        else:
            print("0")
            flag_list[index] = '0'
        p.close()
    except Exception as e:
        print(f"Error in processing index {index}: {e}")

if __name__ == "__main__":
    manager = Manager()
    flag_list = manager.list(['0'] * 471)  # Shared list to store flags

    with Pool(processes=10) as pool:  # Adjust the number of processes as needed
        pool.starmap(solve, [(i, flag_list) for i in range(471)])

    long = int(''.join(flag_list), 2)
    print("FLAG : %s" % l2b(long))