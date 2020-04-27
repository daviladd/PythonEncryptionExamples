import os
import argparse
import random
import hashlib
import struct
from Crypto.Cipher import AES


def file_encrypt(input_filename, encryption_key, output_filename=None, chunk_size=32*1024):
    """ 
    Encrypts a file using AES (CBC mode) with the provided encryption_key.
        input_filename:
            Name of the input file (required)
        encryption_key:
            The encryption key.
            A byte array that must be either 16, 24 or 32 bytes long.
        output_filename (optional):
            Name of the ouptut file.
            If not provided will be the input_filename + '.enc'
        chunk_size (optional):
            Size of the chunk to be read from the input file
            and that will be written to the output file.
    """
    if not output_filename:
        output_filename = input_filename + '.enc'

    initialization_vector = os.urandom(16)
    encryptor = AES.new(encryption_key, AES.MODE_CBC, initialization_vector)
    file_size = os.path.getsize(input_filename)

    with open(input_filename, 'rb') as input_file:
        with open(output_filename, 'wb') as output_file:
            output_file.write(struct.pack('<Q', file_size))
            output_file.write(initialization_vector)

            while True:
                chunk = input_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                output_file.write(encryptor.encrypt(chunk))
    print('File: ' + input_filename + ', has been encrypted to: ' + output_filename)
    return output_filename


def file_decrypt(input_filename, decryption_key, output_filename=None, chunk_size=32*1024):
    """ 
    Decrypts a file using AES (CBC mode) with the provided decryption_key.
        input_filename:
            Name of the input file (required)
        decryption_key:
            The encryption key.
            A byte array that must be either 16, 24 or 32 bytes long.
        output_filename (optional):
            Name of the ouptut file.
            If not provided will be the input_filename + '.dec'
        chunk_size:
            Size of the chunk to be read from the input file
            and that will be written to the output file.
    """
    if not output_filename:
        output_filename = input_filename + '.dec'

    with open(input_filename, 'rb') as input_file:
        original_size = struct.unpack('<Q', input_file.read(struct.calcsize('Q')))[0]
        initialization_vector = input_file.read(16)
        decryptor = AES.new(decryption_key, AES.MODE_CBC, initialization_vector)

        with open(output_filename, 'wb') as output_file:
            while True:
                chunk = input_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                output_file.write(decryptor.decrypt(chunk))

            output_file.truncate(original_size)
    print('File: ' + input_filename + ', has been decrypted to: ' + output_filename)
    return output_filename


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description='Encrypt/Decrypt AES')
    argparser.add_argument('filename', nargs=1)
    argparser.add_argument('password', nargs=1)
    # TODO: add argument for optional output filename
    argparser.add_argument('-e', dest='encrypt', action='store_true')
    argparser.add_argument('-d', dest='decrypt', action='store_true')
    args = argparser.parse_args()

    input_filename = args.filename[0]
    if not os.path.exists(input_filename) or not os.path.isfile(input_filename):
        print('ERROR: No input file has been provided!')
        argparser.print_help()
        quit()

    password = args.password[0]
    if len(password) == 0:
        print('ERROR: No input file has been provided!')
        argparser.print_help()
        quit()

    # Generate a key from the password received:
    key = hashlib.sha256(password.encode()).digest()
    
    # Execute the required operation (if provided):
    if args.encrypt:
        file_encrypt(input_filename, key)
    elif args.decrypt:
        file_decrypt(input_filename, key)
    else:
        argparser.print_help()
        quit()