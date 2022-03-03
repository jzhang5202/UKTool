xor = lambda a, b:list(map(lambda x, y: x ^ y, a, b))

rotl = lambda x, n:((x << n) & 0xffffffff) | ((x >> (32 - n)) & 0xffffffff)

get_uint32_be = lambda key_data:((key_data[0] << 24) | (key_data[1] << 16) | (key_data[2] << 8) | (key_data[3]))

put_uint32_be = lambda n:[((n>>24)&0xff), ((n>>16)&0xff), ((n>>8)&0xff), ((n)&0xff)]

padding = lambda data, block=16: data + [(16 - len(data) % block)for _ in range(16 - len(data) % block)]

unpadding = lambda data: data[:-data[-1]]

list_to_bytes = lambda data: b''.join([bytes((i,)) for i in data])

bytes_to_list = lambda data: [i for i in data]

#分行打印（Arr128 = c_ubyte * 128）类型
def printArry(funname,arry):
    print("%s 值是："%funname)
    for i in range(len(arry)):
        if (i+1)%8 !=0:
            print(hex(arry[i]),end="")
            print(" ", end="")
        else:
            print(hex(arry[i]))
    print("\n")
