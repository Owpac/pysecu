import os
import typing
from argparse import ArgumentParser

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


class Colors:
    FAIL = '\033[91m'
    GREEN = '\033[32m'
    INFO = '\033[93m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class Format:
    INDENT = ' ' * 2
    LIST_SUB = INDENT + "> "
    LIST_TITLE = "[+] "
    LIST_INFO = "[i] "
    LIST_ERROR = "[!] "


def save_file(path: str, content: str) -> None:
    """
    Save a file
    :param path: path of output file
    :param content: content save in the output file
    """
    with open(path, 'w+') as f:
        # The last '\n' is important at the end of a file
        f.write(content + "\n")

    print(Format.LIST_INFO + Colors.GREEN + "File " + os.path.basename(path) + " saved!\n" + Colors.ENDC)


def load_file(path: str) -> str:
    """
    Load a file
    :param path: path of source file to load
    :return content of the loaded file
    """
    with open(path, 'r') as f:
        content = f.read()

    print(Format.LIST_INFO + Colors.GREEN + "File " + os.path.basename(path) + " opened!\n" + Colors.ENDC)

    return content


class Pysecu(object):

    def hash(self, path_input: str, path_output: str) -> None:
        """
        Generate hash of a file
        :param path_input: path of source file
        :param path_output: path of output file
        """
        content = load_file(path_input)
        hash_content = SHA256.new(data=content.encode())

        if path_output:
            save_file(path_output, hash_content.hexdigest())
        else:
            print(hash_content.hexdigest())
            print()

    def generate_rsa_keys(self, number_bits: int, passphrase: str, path_output: str) -> None:
        """
        Generate RSA public and private keys
        :param number_bits: size of RSA keys: 1024, 2048, 4096 bits
        :param passphrase: set passphrase for RSA keys
        :param path_output: path of output file
        """
        # Set files name for private and public keys
        file_name, file_extension = os.path.splitext(path_output)
        public_key_name = file_name + ".pub"
        private_key_name = file_name + ".priv"

        # Check if the input size is correct
        if number_bits in [1024, 2048, 4096]:
            private_key = RSA.generate(number_bits)
            public_key = private_key.publickey()

            save_file(private_key_name, private_key.export_key('PEM', passphrase).decode())

            save_file(public_key_name, public_key.export_key('PEM', passphrase).decode())
        else:
            raise Exception("Wrong bits number: available bits number are 1024, 2048, 4096")

    def encrypt(self, path_input: str, path_public_key: str, passphrase: str, path_output: str) -> None:
        """
        Encrypt a file using RSA public key
        :param path_input: path of source file
        :param path_public_key: path of public RSA key
        :param passphrase: passphrase to decrypt RSA key (set to None if your RSA keys don't have passphrase)
        :param path_output: path of output file
        """
        # Init content, public key and session key
        content = load_file(path_input)
        public_key = RSA.import_key(load_file(path_public_key), passphrase)
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(public_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        cipher_text, tag = cipher_aes.encrypt_and_digest(content.encode())

        # Set files name encrypted content
        file_name, file_extension = os.path.splitext(path_output)

        if path_output:
            with open(file_name + ".bin", 'wb+') as f:
                [f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, cipher_text)]
        else:
            print([x for x in (enc_session_key, cipher_aes.nonce, tag, cipher_text)])

    def decrypt(self, path_input: str, path_private_key: str, passphrase: str, path_output: str) -> None:
        """
        Decrypt a file using RSA private key
        :param path_input: path of source file
        :param path_private_key: path of private RSA key
        :param passphrase: passphrase to decrypt RSA key (set to None if your RSA keys don't have passphrase)
        :param path_output: path of output file
        """
        # Init private key
        private_key = RSA.import_key(load_file(path_private_key), passphrase)
        with open(path_input, 'rb') as f:
            enc_session_key, nonce, tag, cipher_text = [f.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        content = cipher_aes.decrypt_and_verify(cipher_text, tag)

        if path_output:
            with open(path_output, 'w+') as f:
                [f.write(x.decode()) for x in (enc_session_key, cipher_aes.nonce, tag, cipher_text)]
        else:
            print(content.decode())

    # Bug in return of SHA256.new() so we disabled inspection to avoid highlights
    # noinspection PyTypeChecker
    def sign(self, path_input: str, path_private_key: str, path_public_key: str, passphrase: str) -> None:
        """
        Sign and verify signature of a file
        :param path_input: path of source file
        :param path_private_key:
        :param path_public_key:
        :param passphrase:
        """
        # Init content, private and public keys
        content = load_file(path_input)
        private_key = RSA.import_key(load_file(path_private_key), passphrase)
        public_key = RSA.import_key(load_file(path_public_key), passphrase)

        # Hash and sign content
        hash_content = SHA256.new(data=content.encode())
        signature = pss.new(private_key).sign(hash_content)

        # Verify signature of the content
        verify = pss.new(public_key)
        try:
            verify.verify(hash_content, signature)
            print(Format.LIST_INFO + Colors.INFO + "The signature is authentic!\n" + Colors.ENDC)
        except (ValueError, TypeError):
            print(Format.LIST_ERROR + Colors.FAIL + "The signature is not authentic!\n" + Colors.ENDC)


SAMPLES = """Type python3 pysecu.py -h to show help

Command line examples:
    1- Hash a file and print the result:
        $ python3 pysecu.py -i file.txt
        
    2- Hash a file and save the result in a file:
        $ python3 pysecu.py -i file.txt -o file.hash

    3- Generate private and public RSA keys:
        $ python3 pysecu.py -rsa -o mykey
        
        This will generate mykey.pub and mykey.priv
        
        $ python3 pysecu.py -rsa -s 4096 -p thisismypassphrase -o mykey
        
        This will the same files as before, but you will have your keys with 4096 bits (2048 is default) and 
        a your keys will be encrypted with the passphrase.
        
    4- Encrypt a file using public key:
        $ python3 pysecu.py -i file.txt -pkey mykey.pub -p passphrase -o file.bin
    
    5- Decrypt a file using private key:
        $ python3 pysecu.py -i file.bin -pkey mykey.priv -p passphrase -o file.txt
        
    6- Sign a file and verify it signature:
        $ python3 pysecu.py -i file.txt -s mykey.priv -v mykey.pub
    """


def main():
    argp = ArgumentParser(
        description="Pysecu",
        usage="python3 pysecu.py [options] \nsamples: python3 pysecu.py")

    argp.add_argument('-rsa', '--rsa-keys', dest='rsa', action="store_true",
                      help='Generate RSA keys')

    argp.add_argument('-b', '--bits', dest='bits', type=int,
                      help='Set number of bits of your keys: 1024, 2048, 4096')

    argp.add_argument('-p', '--passphrase', dest='passphrase', type=str,
                      help='Set a passphrase for your keys')

    argp.add_argument('-i', '--input', dest='input', type=str,
                      help='Path of source file')

    argp.add_argument('-o', '--output', dest='output', type=str,
                      help='Path of output file')

    argp.add_argument('-e', '--encrypt', dest='encrypt', action="store_true",
                      help='Encrypt a file with RSA')

    argp.add_argument('-d', '--decrypt', dest='decrypt', action="store_true",
                      help='Decrypt a file with RSA')

    argp.add_argument('-pkey', '--pkey', dest='pkey', type=str,
                      help='Get either a public or private key')

    argp.add_argument('-s', '--sign', dest='sign', type=str,
                      help='Sign a file with a private key')

    argp.add_argument('-v', '--verify', dest='verify', type=str,
                      help='Verify a signature with a public key')

    args = argp.parse_args()

    pysecu = Pysecu()

    print()

    try:
        if args.input:
            if args.sign:
                pysecu.sign(args.input, args.sign, args.verify, args.passphrase)
            elif args.encrypt:
                pysecu.encrypt(args.input, args.pkey, args.passphrase, args.output)
            elif args.decrypt:
                pysecu.decrypt(args.input, args.pkey, args.passphrase, args.output)
            else:
                pysecu.hash(args.input, args.output)

        elif args.rsa:
            if args.bits:
                pysecu.generate_rsa_keys(args.bits, args.passphrase, args.output)
            else:
                pysecu.generate_rsa_keys(2048, args.passphrase, args.output)

        else:
            print(SAMPLES)
    except Exception as e:
        print(Colors.FAIL + Colors.BOLD + Format.LIST_ERROR + "ERROR: " + Colors.ENDC + str(e) + "\n")


if __name__ == "__main__":
    main()
