import os,base64,time
from Crypto.Cipher import AES
from Crypto.Hash import MD5,SHA
import sys

with open('key.txt') as f:
    key = f.read()[:16]

def pad(msg):
    pad_length = 16-len(msg)%16
    return msg+chr(pad_length)*pad_length

def unpad(msg):
    return msg[:-ord(msg[-1])]

def encrypt(iv,msg):
    msg = pad(msg)
    cipher = AES.new(key,AES.MODE_CBC,iv)
    encrypted = cipher.encrypt(msg)
    return encrypted

def decrypt(iv,msg):
    cipher = AES.new(key,AES.MODE_CBC,iv)
    decrypted = cipher.decrypt(msg)
    decrypted = unpad(decrypted)
    return decrypted

def send_msg(msg):
    iv = 'xa05md62ld8sdns3'
    encrypted = encrypt(iv,msg)
    msg = iv+encrypted
    msg = base64.b64encode(msg)
    print msg
    return

def recv_msg():
    msg = raw_input()
    try:
        msg = base64.b64decode(msg)
        iv = msg[:16]
        decrypted = decrypt(iv,msg[16:])
        return decrypted
    except Exception:
        print 'Error'
        exit(0)


if __name__ == '__main__':
    with open('flag.txt') as f:
        flag = f.read().strip()
    assert flag.startswith('hitcon{') and flag.endswith('}')
    send_msg('Welcome!!')
    while True:
        try:
            msg = recv_msg().strip()
            if msg.startswith('exit'):
                exit(0)
            elif msg.startswith('echo'):
                send_msg(msg[4:])
            elif msg.startswith('time'):
                send_msg(str(time.time()))
            elif msg.startswith('get-flag'):
                send_msg(flag)
            elif msg.startswith('md5'):
                send_msg(MD5.new(msg[3:]).digest())
            elif msg.startswith('sha1'):
                send_msg(SHA.new(msg[4:]).digest())
            else:
                send_msg('command not found')
        except:
            exit(0)
