import os
from argparse import ArgumentParser

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss


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


class Pysecu(object):

    def save_file(self, path, content):
        with open(path, 'w+') as f:
            f.write(content + "\n")

        print(Format.LIST_INFO + Colors.GREEN + "File " + os.path.basename(path) + " saved!\n" + Colors.ENDC)

    def load_file(self, path):
        with open(path, 'r') as f:
            content = f.read()

        print(Format.LIST_INFO + Colors.GREEN + "File " + os.path.basename(path) + " opened!\n" + Colors.ENDC)

        return content

    def hash(self, path_input, path_output):
        content = self.load_file(path_input)

        hash_content = SHA256.new(data=content.encode())

        if path_output:
            self.save_file(path_output, hash_content.hexdigest())
        else:
            print(hash_content.hexdigest())
            print()

    def generate_rsa_keys(self, number_bits, passphrase, path_output):

        dir_name = os.path.dirname(path_output)
        file_name, file_extension = os.path.splitext(path_output)
        public_key_name = file_name + ".pub"
        private_key_name = file_name + ".priv"

        if number_bits in [1024, 2048, 4096]:
            private_key = RSA.generate(number_bits)
            public_key = private_key.publickey()

            self.save_file(os.path.join(dir_name, private_key_name),
                           private_key.export_key('PEM', passphrase).decode() + "\n")

            self.save_file(os.path.join(dir_name, public_key_name),
                           public_key.export_key('PEM', passphrase).decode() + "\n")
        else:
            raise Exception("Wrong bits number: available bits number are 1024, 2048, 4096")

    def sign(self, path_input, path_private_key, path_public_key, passphrase):
        content = self.load_file(path_input)

        hash_content = SHA256.new(data=content.encode())

        private_key = RSA.import_key(self.load_file(path_private_key), passphrase)

        public_key = RSA.import_key(self.load_file(path_public_key), passphrase)

        signature = pss.new(private_key).sign(hash_content)

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
        
    4- Sign a file and verify it signature:
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
                      help='Get a file')

    argp.add_argument('-o', '--output', dest='output', type=str,
                      help='Save the output in a file')

    argp.add_argument('-s', '--sign', dest='sign', type=str,
                      help='Sign a file')

    argp.add_argument('-v', '--verify', dest='verify', type=str,
                      help='Verify a signature')

    args = argp.parse_args()

    pysecu = Pysecu()

    print()

    try:
        if args.input:
            if args.sign:
                pysecu.sign(args.input, args.sign, args.verify, args.passphrase)
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
