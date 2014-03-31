#!/usr/bin/env python
import getpass
import optparse
import os
import sys
import unittest
from random import randrange
from hashlib import md5
from os import urandom

PY3 = sys.version_info[0] == 3
if PY3:
    import builtins
    print_ = getattr(builtins, 'print')
    raw_input = getattr(builtins, 'input')
else:
    def print_(s):
        sys.stdout.write(s)
        sys.stdout.write('\n')

try:
    from cStringIO import StringIO
except ImportError:
    if PY3:
        from io import StringIO
    else:
        from StringIO import StringIO

from Crypto.Cipher import Blowfish
from Crypto.Cipher import AES
from Crypto import Random

__BLOWFISH__ = 1
__AES__ = 2

def _gen_padding(file_size, block_size):
    pad_bytes = block_size - (file_size % block_size)
    padding = Random.get_random_bytes(pad_bytes - 1)
    bflag = randrange(block_size - 2, 256 - block_size)
    bflag -= bflag % block_size - pad_bytes
    return padding + chr(bflag)


def _read_padding(buffer, block_size):
    return (ord(buffer[-1]) % block_size) or block_size


def generate_iv(block_size):
    return Random.get_random_bytes(block_size)


def derive_key_and_iv(password, salt, key_length, iv_length):
    """

    :param password:
    :param salt:
    :param key_length:
    :param iv_length:
    :return: (key, iv)
    """
    d = d_i = b''
    while len(d) < key_length + iv_length:
            d_i = md5(d_i + str.encode(password) + salt).digest()
            d += d_i
    return d[:key_length], d[key_length:key_length + iv_length]


def get_blowfish_cipher(key, iv):
    return Blowfish.new(key, Blowfish.MODE_CBC, iv)


def get_aes_cipher(key, iv):
    return AES.new(key, AES.MODE_CBC, iv)


def encrypt(in_buf, out_buf, password, chunk_size=4096, cipher_type=__BLOWFISH__, salt_header=''):
    """

    :param in_buf:
    :param out_buf:
    :param password:
    :param chunk_size:
    :param cipher_type:
    :param salt_header:
    :raise AttributeError:
    """

    if cipher_type == __BLOWFISH__:
        salt = urandom(Blowfish.block_size - len(salt_header))
        key, iv = derive_key_and_iv(password=password, salt=salt, key_length=32, iv_length=Blowfish.block_size)
        cipher = get_blowfish_cipher(password, iv)
    elif cipher_type == __AES__:
        salt = urandom(AES.block_size - len(salt_header))
        key, iv = derive_key_and_iv(password=password, salt=salt, key_length=32, iv_length=AES.block_size)
        cipher = get_aes_cipher(key, iv)
    else:
        raise AttributeError("Unknown cipher type")

    out_buf.write(str.encode(salt_header) + salt)
    bytes_read = 0
    wrote_padding = False

    while 1:
        buffer = in_buf.read(chunk_size)
        buffer_len = len(buffer)
        bytes_read += buffer_len
        if buffer:
            if buffer_len < chunk_size:
                buffer += _gen_padding(bytes_read, cipher.block_size)
                wrote_padding = True
            out_buf.write(cipher.encrypt(buffer))
        else:
            if not wrote_padding:
                out_buf.write(cipher.encrypt(_gen_padding(bytes_read, cipher.block_size)))
            break


def decrypt(in_buf, out_buf, password, chunk_size=4096, salt_header='', cipher_type=__BLOWFISH__):

    """

    :param in_buf:
    :param out_buf:
    :param password:
    :param chunk_size:
    :param salt_header:
    :param cipher_type:
    :raise AttributeError:
    """

    if cipher_type == __BLOWFISH__:
        salt = in_buf.read(Blowfish.block_size)[len(salt_header):]
        key, iv = derive_key_and_iv(password=password, salt=salt, key_length=32, iv_length=Blowfish.block_size)
        cipher = get_blowfish_cipher(password, iv)
    elif cipher_type == __AES__:
        salt = in_buf.read(AES.block_size)[len(salt_header):]
        key, iv = derive_key_and_iv(password=password, salt=salt, key_length=32, iv_length=AES.block_size)
        cipher = get_aes_cipher(key, iv)
    else:
        raise AttributeError("Unknown cipher type")

    decrypted = ''

    while 1:
        buffer = in_buf.read(chunk_size)
        if buffer:
            decrypted = cipher.decrypt(buffer)
            out_buf.write(decrypted)
        else:
            break

    if decrypted:
        padding = _read_padding(decrypted, cipher.block_size)
        out_buf.seek(-padding, 2)
        out_buf.truncate()


def encrypt_file(in_file, out_file, key, chunk_size=4096, cipher_type=__BLOWFISH__):
    with open(in_file, 'rb') as in_fh:
        with open(out_file, 'wb') as out_fh:
            encrypt(in_fh, out_fh, key, chunk_size, cipher_type=cipher_type)


def decrypt_file(in_file, out_file, key, chunk_size=4096, cipher_type=__BLOWFISH__):
    with open(in_file, 'rb') as in_fh:
        with open(out_file, 'wb') as out_fh:
            decrypt(in_fh, out_fh, key, chunk_size, cipher_type=cipher_type)


class TestEncryptDecrypt(unittest.TestCase):
    def setUp(self):
        self.in_filename = '/tmp/crypt.tmp.in'
        self.out_filename = '/tmp/crypt.tmp.out'
        self.dec_filename = '/tmp/crypt.tmp.dec'
        self.key = 'testkey'

    def tearDown(self):
        self.remove_files(
            self.in_filename,
            self.out_filename,
            self.dec_filename,
        )

    def remove_files(self, *filenames):
        for fn in filenames:
            if os.path.exists(fn):
                os.unlink(fn)

    def write_bytes(self, num, ch='a'):
        buf = ch * num
        with open(self.in_filename, 'wb') as fh:
            fh.write(buf)
        return buf

    def crypt_data(self, num_bytes, ch, in_key=None, out_key=None, chunk_size=4096, cipher_type=__BLOWFISH__):
        in_key = in_key or self.key
        out_key = out_key or self.key

        buf = self.write_bytes(num_bytes, ch)
        encrypt_file(self.in_filename, self.out_filename, in_key, chunk_size, cipher_type=cipher_type)
        decrypt_file(self.out_filename, self.dec_filename, out_key, chunk_size, cipher_type=cipher_type)

        with open(self.dec_filename, 'rb') as fh:
            decrypted = fh.read()

        return buf, decrypted

    def test_encrypt_decrypt(self):
        def encrypt_flow(ch):
            for i in range(17):
                buf, decrypted = self.crypt_data(i, ch)
                self.assertEqual(buf, decrypted)

        encrypt_flow('a')
        encrypt_flow('\x00')
        encrypt_flow('\x01')
        encrypt_flow('\xff')

    def test_encrypt_decrypt_blowfish(self):
        def encrypt_flow(ch):
            for i in range(17):
                buf, decrypted = self.crypt_data(i, ch, cipher_type=__BLOWFISH__)
                self.assertEqual(buf, decrypted)

        encrypt_flow('a')
        encrypt_flow('\x00')
        encrypt_flow('\x01')
        encrypt_flow('\xff')

    def test_encrypt_decrypt_aes(self):
        def encrypt_flow(ch):
            for i in range(17):
                buf, decrypted = self.crypt_data(i, ch, cipher_type=__AES__)
                self.assertEqual(buf, decrypted)

        encrypt_flow('a')
        encrypt_flow('\x00')
        encrypt_flow('\x01')
        encrypt_flow('\xff')

    def test_key(self):
        buf, decrypted = self.crypt_data(128, 'a', self.key, self.key + 'x')
        self.assertNotEqual(buf, decrypted)

    def test_chunk_sizes(self):
        for i in [128, 1024, 2048, 4096]:
            nb = [i - 1, i, i + 1, i * 2, i * 2 + 1]
            for num_bytes in nb:
                buf, decrypted = self.crypt_data(num_bytes, 'a', chunk_size=i)
                self.assertEqual(buf, decrypted)

    def test_stringio(self):
        for i in [128, 1024, 2048, 4096]:
            nb = [i - 1, i, i + 1, i * 2, i * 2 + 1]
            for num_bytes in nb:
                in_buf = StringIO()
                out_buf = StringIO()
                dec_buf = StringIO()
                in_buf.write(num_bytes * 'a')
                in_buf.seek(0)
                encrypt(in_buf, out_buf, self.key, i)
                out_buf.seek(0)
                decrypt(out_buf, dec_buf, self.key, i)
                self.assertEqual(in_buf.getvalue(), dec_buf.getvalue())


if __name__ == '__main__':
    parser = optparse.OptionParser(usage='%prog [-e|-d] INFILE OUTFILE')
    parser.add_option('-t', '--test', dest='run_tests', action='store_true')
    parser.add_option('-k', '--key', dest='key', action='store', type='str')
    parser.add_option('-e', '--encrypt', dest='encrypt', action='store_true')
    parser.add_option('-d', '--decrypt', dest='decrypt', action='store_true')
    parser.add_option('-q', '--quiet', dest='quiet', action='store_true')
    (options, args) = parser.parse_args()

    if options.run_tests:
        unittest.main(argv=sys.argv[:1], verbosity=not options.quiet and 2 or 0)

    if len(args) == 1:
        if options.encrypt:
            default = '%s.e' % args[0]
        else:
            default = args[0].rstrip('.e')
        args.append(raw_input('Destination? (%s) ' % default) or default)

    if len(args) < 2 or not (options.encrypt or options.decrypt):
        parser.print_help()
        sys.exit(1)

    if not options.key:
        while 1:
            key = getpass.getpass('Key: ')
            verify = getpass.getpass('Verify: ')
            if key == verify:
                break
            else:
                print_('Keys did not match')
    else:
        key = options.key

    infile, outfile = args[0], args[1]
    if os.path.exists(outfile):
        print_('%s will be overwritten' % outfile)
        if raw_input('Continue? yN ') != 'y':
            sys.exit(2)

    if options.encrypt:
        encrypt_file(infile, outfile, key)
    else:
        decrypt_file(infile, outfile, key)
