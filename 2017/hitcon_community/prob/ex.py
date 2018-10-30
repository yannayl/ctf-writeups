from pwn import *
from prob import decrypt, pad
from Crypto.Hash import MD5,SHA
from string import printable

#context.log_level = "debug"

charset = list(printable) + map(chr, range(1,17))
iv_remote = 'xa05md62ld8sdns3'

r = process(['python', 'prob.py'])
#r = remote('pwnhub.tw', 12345, timeout=20)

def sendmsg(iv, c):
    debug("send message: " + decrypt(iv, c))
    msg = iv + c
    msg = msg.encode('base64')
    msg = msg.replace('\n', '') + '\n'
    r.send(msg)

def recvmsg():
    m = ''
    while True:
        try:
            l = r.recvline()
            m = l.decode('base64')
            break
        except:
            warn("bad line: " + l)
    iv = m[:16]
    c = m[16:]
    debug("recv message: " + decrypt(iv, c))
    return iv,c

def sr(iv, c):
    sendmsg(iv, c)
    iv, c = recvmsg()
    assert iv == iv_remote
    return c


def xor(a1, a2, a3):
    ret = []
    for x1, x2, x3 in zip(a1, a2, a3):
        ret.append(ord(x1) ^ ord(x2) ^ ord(x3))

    ret = ''.join(chr(c) for c in ret)
    debug('\n' + hexdump(a1+a2+a3+ret))
    return ret


def create_iv(msg, iv, msg_new, size=-1):
    msg = pad(msg)
    if -1 != size:
        msg = msg[:-1] + chr(size)

    return xor(iv, msg, pad(msg_new))

iv_remote, c_welcome = recvmsg()
m_welcome  = 'Welcome!!'


info('send get-flag')
iv = create_iv(m_welcome, iv_remote, 'get-flag')
c_flag = sr(iv, c_welcome)

flag = 'hitcon{'
iv = create_iv(m_welcome, iv_remote, 'echo')
c_empty = sr(iv, c_welcome)

for last_byte in charset:
    debug('try %c' % last_byte)

    iv = create_iv(flag, iv_remote, 'echo', size=ord(last_byte))
    if sr(iv, c_flag[:16]) == c_empty:
        info("found block last character - %c" % last_byte)
        break
else:
    error('faied to find block\'s last byte')
    exit(-1)

while len(flag) < 15:
    info('getting flag char %d' % (len(flag) + 1))
    
    for c in charset:
        cand = flag + c
        debug('try ' + cand)
        iv = create_iv(m_welcome, iv_remote, 'echo' + cand[4:])
        c_cand = sr(iv, c_welcome[:16])

        iv = create_iv(cand, iv_remote, 'echo' + cand[4:], size=ord(last_byte))
        if c_cand == sr(iv, c_flag[:16]):
            flag = cand
            info('found ' + cand)
            break
    else:
        break

flag = flag + last_byte
info('flag first block: ' + flag)

info('skip flag fist 12 bytes')
iv = create_iv(flag[:4], iv_remote, 'echo')
c_flag4 = sr(iv, c_flag)
iv = create_iv(flag[4:8], iv_remote, 'echo')
c_flag8 = sr(iv, c_flag4)
iv = create_iv(flag[8:12], iv_remote, 'echo')
c_flag12 = sr(iv, c_flag8)

info("looking for next block last byte")
for last_byte in charset:
    debug('try %c' % last_byte)

    iv = create_iv(flag[12:], iv_remote, 'echo', size=ord(last_byte))
    if sr(iv, c_flag12[:16]) == c_empty:
        info("found block last character - %c" % last_byte)
        break
else:
    error('faied to find block\'s last byte')
    exit(-1)

while len(flag) < 12 + 15:
    info('getting flag char %d' % (len(flag) + 1))
    
    for c in charset:
        cand = flag[12:] + c
        debug('try ' + cand)
        iv = create_iv(m_welcome, iv_remote, 'echo' + cand[4:])
        c_cand = sr(iv, c_welcome[:16])

        iv = create_iv(cand, iv_remote, 'echo' + cand[4:], size=ord(last_byte))
        if c_cand == sr(iv, c_flag12[:16]):
            flag = flag + c
            info('found ' + flag)
            break
    else:
        error('falied to find next char')
        exit(-1)

    if last_byte == flag[-1]:
        break

info('found flag: ' + flag[:-1])

