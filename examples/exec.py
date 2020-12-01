import os
import pwd
import socket

from ssh.session import Session
from ssh import options

# Linux only
USERNAME = pwd.getpwuid(os.geteuid()).pw_name
HOST = 'localhost'
PORT = 22

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

s = Session()
s.options_set(options.HOST, HOST)
s.options_set(options.USER, USERNAME)
s.options_set_port(PORT)
s.set_socket(sock)
s.connect()

# Authenticate with agent
s.userauth_agent(USERNAME)

chan = s.channel_new()
chan.open_session()
chan.request_exec('echo me')
size, data = chan.read()
while size > 0:
    print(data.strip())
    size, data = chan.read()
chan.close()
