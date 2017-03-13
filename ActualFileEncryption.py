from Crypto.Cipher import AES
from Crypto import Random
from hashlib import md5
import click


@click.command()
@click.option('getkey&iv')
def get_key_and_iv(password, salt, key_len, iv_len):
    '''MD5 digest algorithm; generates a 16 byte string for the key and iv values '''
    d = d_i = ''

    while len(d) < key_len + iv_len:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len + iv_len]


@click.option('encrypt')
def encrypt(in_file, out_file, password, key_len=32):
    '''Encrypts the file in AES format; both the block sizes and keys must be any multiple of 32'''
    block_size = AES.block_size
    salt = Random.new().read(block_size - len('Salted__'))
    key, iv = get_key_and_iv(password, salt, key_len, block_size)
    ciph = AES.new(key, AES.MODE_CBC, iv)
    out_file.write('Salted__' + salt)
    #finished process
    fin = False

    while not fin:
        chunk = in_file.read(1024 * block_size)
        if len(chunk) == 0 or len(chunk) % block_size != 0:
            padding_len = block_size - (len(chunk) % block_size)
            chunk += padding_len * chr(padding_len)
            fin = True
        out_file.write(ciph.encrypt(chunk))


@click.option('decrypt')
def decrypt(in_file, out_file, password, key_len=32):
    '''Decrypts the file.'''
    block_size = AES.block_size
    salt = in_file.read(block_size)[len('Salted__'):]
    key, iv = get_key_and_iv(password, salt, key_len, block_size)
    ciph = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    fin = False

    while not fin:
        chunk, next_chunk = next_chunk, ciph.decrypt(in_file.read(1024 * block_size))
        if len(next_chunk) == 0:
            padding_len = ord(chunk[-1])
            if padding_len < 1 or padding_len > block_size:
                raise ValueError("bad decryption padding (%d)" % padding_len)
            # padding must be the same
            if chunk[-padding_len:] != (padding_len * chr(padding_len)):
                raise ValueError("bad decryption")
            chunk = chunk[:-padding_len]
            fin = True
        out_file.write(chunk)
