import argparse
import getpass
import socket
import sys

from ssh import key, keytypes


parser = argparse.ArgumentParser(description='keygen.py -- like ssh-keygen(1)')
parser.add_argument('-t', dest='type', help='Key type', default='ed25519', choices=(
    'rsa', 'ed25519', 'dss'
))
parser.add_argument('-f', dest='file', help='Output private key file', required=True)
parser.add_argument('-b', dest='bits', type=int, default=2048, help='Number of key bits')
args = parser.parse_args()

key_type = keytypes.key_type_from_name('ssh-' + args.type)

if isinstance(key_type, keytypes.DSSKey):
    if args.bits != 1024:
        print('dss keys only support 1024 bits in OpenSSH. Setting -b 1024.', file=sys.stderr)
    args.bits = 1024
if isinstance(key_type, keytypes.ED25519Key):
    args.bits = 0

keypair = key.generate(key_type, args.bits)

keypair.export_privkey_file(args.file)
pubkey = keypair.export_pubkey_base64().decode()
pubkey_openssh_format = ' '.join((str(key_type), pubkey, '%s@%s' % (getpass.getuser(), socket.getfqdn())))
print(pubkey_openssh_format)
with open(args.file + '.pub', 'w') as fd:
    print(pubkey_openssh_format, file=fd)
