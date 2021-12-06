from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from os import urandom

import time


def pad(text):
    while len(text) % 8 != 0:
        text += b' '
    return text


def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(max(len(a), len(b)), byteorder="big")


def generate_8_bytes(file_name):
    with open(file_name, "wb") as file:
        key = urandom(8)
        file.write(key)
    return key


def reading_binary_file(file_name):
    with open(file_name, 'rb') as file:
        text = file.read()
    return text


def writing_binary_file(file_name, text):
    with open(file_name, "wb") as file:
        file.write(text)
    file.close()


class DES3_ECB(object):

    def __init__(self, key_one, key_two, key_three):
        self._key_one = key_one
        self._key_two = key_two
        self._key_three = key_three

    def encrypt(self, file_text, file_encode):
        des_one = DES.new(self._key_one, DES.MODE_ECB)
        des_two = DES.new(self._key_two, DES.MODE_ECB)
        des_three = DES.new(self._key_three, DES.MODE_ECB)

        with open(file_text, "r") as f_text:
            with open(file_encode, "wb+") as f_encode:
                text = f_text.read()

                text = des_one.encrypt(text.encode())
                text = des_two.encrypt(text)
                text = des_three.encrypt(text)

                f_encode.write(text)

    def decrypt(self, file_encode, file_text):
        des_one = DES.new(self._key_one, DES.MODE_ECB)
        des_two = DES.new(self._key_two, DES.MODE_ECB)
        des_three = DES.new(self._key_three, DES.MODE_ECB)

        with open(file_encode, 'rb') as f_encode:
            with open(file_text, "w+") as f_text:
                text = f_encode.read()

                text = des_three.decrypt(text)
                text = des_two.decrypt(text)
                text = des_one.decrypt(text)

                f_text.write(text.decode())


class DES3_inner_CBC(object):

    def __init__(self, key_one, key_two, key_three, IV):
        self._key_one = key_one
        self._key_two = key_two
        self._key_three = key_three
        self._IV = IV

    def encrypt(self, file_text, file_encode):
        des_one = DES.new(self._key_one, DES.MODE_ECB)
        des_two = DES.new(self._key_two, DES.MODE_ECB)
        des_three = DES.new(self._key_three, DES.MODE_ECB)

        IV = [self._IV, self._IV, self._IV]
        with open(file_text, "r") as f_text:
            with open(file_encode, "wb+") as f_encode:
                while text_block := f_text.read(8):
                    text_block = bitwise_xor_bytes(text_block.encode(), IV[0])
                    text_block = des_one.encrypt(text_block)
                    IV[0] = text_block

                    text_block = bitwise_xor_bytes(text_block, IV[1])
                    text_block = des_two.decrypt(text_block)
                    IV[1] = text_block

                    text_block = bitwise_xor_bytes(text_block, IV[2])
                    text_block = des_three.encrypt(text_block)
                    IV[2] = text_block

                    f_encode.write(text_block)

    def decrypt(self, file_encode, file_text):
        des_one = DES.new(self._key_one, DES.MODE_ECB)
        des_two = DES.new(self._key_two, DES.MODE_ECB)
        des_three = DES.new(self._key_three, DES.MODE_ECB)

        IV = [self._IV, self._IV, self._IV]
        new_IV = [b"", b"", b""]
        with open(file_encode, 'rb') as f_encode:
            with open(file_text, "w+") as f_text:
                while text_block := f_encode.read(8):
                    new_IV[2] = text_block
                    text_block = des_three.decrypt(text_block)
                    text_block = bitwise_xor_bytes(text_block, IV[2])

                    new_IV[1] = text_block
                    text_block = des_two.encrypt(text_block)
                    text_block = bitwise_xor_bytes(text_block, IV[1])

                    new_IV[0] = text_block
                    text_block = des_one.decrypt(text_block)
                    text_block = bitwise_xor_bytes(text_block, IV[0])

                    IV = new_IV.copy()

                    f_text.write(text_block.decode())


class DES3_outer_CBC(object):

    def __init__(self, key_one, key_two, key_three, IV):
        self._key_one = key_one
        self._key_two = key_two
        self._key_three = key_three
        self._IV = IV

    def encrypt(self, file_text, file_encode):
        des_one = DES.new(self._key_one, DES.MODE_ECB)
        des_two = DES.new(self._key_two, DES.MODE_ECB)
        des_three = DES.new(self._key_three, DES.MODE_ECB)

        IV = self._IV
        with open(file_text, "r") as f_text:
            with open(file_encode, "wb+") as f_encode:
                while text_block := f_text.read(8):
                    text_block = bitwise_xor_bytes(text_block.encode(), IV)

                    text_block = des_one.encrypt(text_block)
                    text_block = des_two.decrypt(text_block)
                    text_block = des_three.encrypt(text_block)

                    IV = text_block

                    f_encode.write(text_block)

    def decrypt(self, file_encode, file_text):
        des_one = DES.new(self._key_one, DES.MODE_ECB)
        des_two = DES.new(self._key_two, DES.MODE_ECB)
        des_three = DES.new(self._key_three, DES.MODE_ECB)

        IV = self._IV
        with open(file_encode, 'rb') as f_encode:
            with open(file_text, "w+") as f_text:
                while text_block := f_encode.read(8):
                    new_IV = text_block

                    text_block = des_three.decrypt(text_block)
                    text_block = des_two.encrypt(text_block)
                    text_block = des_one.decrypt(text_block)

                    text_block = bitwise_xor_bytes(text_block, IV)

                    IV = new_IV

                    f_text.write(text_block.decode())


class DES3_with_padding(object):
    def __init__(self, key_one, key_two, key_three):
        self._key_one = key_one
        self._key_two = key_two
        self._key_three = key_three

    def encrypt(self, file_text, file_encode):
        des_one = DES.new(self._key_one, DES.MODE_ECB)
        des_two = DES.new(self._key_two, DES.MODE_ECB)
        des_three = DES.new(self._key_three, DES.MODE_ECB)

        with open(file_text, "r") as f_text:
            with open(file_encode, "wb+") as f_encode:
                text = f_text.read()

                text = des_one.encrypt(text.encode())
                rand = urandom(4)
                text = rand + text + rand

                text = des_two.encrypt(text)
                rand = urandom(4)
                text = rand + text + rand

                text = des_three.encrypt(text)

                f_encode.write(text)


    def decrypt(self, file_encode, file_text):
        des_one = DES.new(self._key_one, DES.MODE_ECB)
        des_two = DES.new(self._key_two, DES.MODE_ECB)
        des_three = DES.new(self._key_three, DES.MODE_ECB)

        with open(file_encode, 'rb') as f_encode:
            with open(file_text, "w+") as f_text:
                text = f_encode.read()

                text = des_three.decrypt(text)

                text = text[4:len(text) - 4]
                text = des_two.decrypt(text)

                text = text[4:len(text) - 4]
                text = des_one.decrypt(text)

                f_text.write(text.decode())



key_one = generate_8_bytes("key_one.bin")
key_two = generate_8_bytes("key_two.bin")
key_three = generate_8_bytes("key_three.bin")

IV = generate_8_bytes("IV.bin")

des3_ecb = DES3_ECB(key_one, key_two, key_three)
des3_inner_cbc = DES3_inner_CBC(key_one, key_two, key_three, IV)
des3_outer_cbc = DES3_outer_CBC(key_one, key_two, key_three, IV)
des3_with_padding = DES3_with_padding(key_one, key_two, key_three)

file = "files_for_encryption/100mb.txt"

start_time = time.time()
des3_ecb.encrypt(file, file[21:len(file) - 4] + "_encode_ecb.bin")
print("ENC--- %s seconds ---" % (time.time() - start_time))


start_time = time.time()
des3_ecb.decrypt(file[21:len(file) - 4] + "_encode_ecb.bin", file[21:len(file) - 4] + "_decode_ecb.txt")
print("DEC--- %s seconds ---" % (time.time() - start_time))
print("\n")



'''
# -------------------------------------------------------------------------------------- #


# ------------------------------------------------------------------------------------------ #

start_time = time.time()
des3_inner_cbc.encrypt(file, file[21:len(file) - 4] + "_encode_inn.bin")
print("ENC--- %s seconds ---" % (time.time() - start_time))


start_time = time.time()
des3_inner_cbc.decrypt(file[21:len(file) - 4] + "_encode_inn.bin", file[21:len(file) - 4] + "_decode_inn.txt")
print("DEC--- %s seconds ---" % (time.time() - start_time))
print("\n")
# ------------------------------------------------------------------------------------------ #

start_time = time.time()
des3_outer_cbc.encrypt(file, file[21:len(file) - 4] + "_encode_out.bin")
print("ENC--- %s seconds ---" % (time.time() - start_time))


start_time = time.time()
des3_outer_cbc.decrypt(file[21:len(file) - 4] + "_encode_out.bin", file[21:len(file) - 4] + "_decode_out.txt")
print("DEC--- %s seconds ---" % (time.time() - start_time))
print("\n")
# ------------------------------------------------------------------------------------------ #

start_time = time.time()
des3_with_padding.encrypt(file, file[21:len(file) - 4] + "_encode_padd.bin")
print("ENC--- %s seconds ---" % (time.time() - start_time))


start_time = time.time()
des3_with_padding.decrypt(file[21:len(file) - 4] + "_encode_padd.bin", file[21:len(file) - 4] + "_decode_padd.txt")
print("DEC--- %s seconds ---" % (time.time() - start_time))
print("\n")

'''