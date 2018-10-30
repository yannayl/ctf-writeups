from task import *
import socket

addr = ('pki.hackable.software',1337)
n1 = '3473610a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c7c3252c8d653f6e08707032329bde4b960bb1d78477243b293a40be719aa5a4c4fcc1c3ecf420ec6b4a7623b775ac6620a109cef4bf74db4fa69d7bd7a12562acdbcd3fc9880790bd2da6f8a7634c34ac29f90101bae01cd5fb13c94c297d1eef9856de6c729741b1b3adefb01958ec1007653d0e62f792b618c57eea6bcdd9'
n2 = '3473610a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c7c3252c8d653f6e08707032329bde4b960bb1578477243b293a40be719aa5a4c4fcc1c3ecf420ec6b4a7623b7f5ac6620a109cef4bf74db4fa69dfbd7a12562acdbcd3fc9880790bd2da6f8a7634c34ac29f98101bae01cd5fb13c94c297d1eef9856de6c729741b1b3adefb09957ec1007653d0e62f792b618c5feea6bcdd9'
n1 = (n1 + '00' * 40).decode('hex')
n2 = (n2 + '00' * 40).decode('hex')

name = 'c'

base = pow(2, 320)
e = 2 ** 16 + 1
d = modinv(e, base / 2)

## make sure we have a K collision
assert h(makeK(name,n1)) == h(makeK(name,n2))
assert h(makeMsg(name,n1)) != h(makeMsg(name,n2))

def b64(s):
	return s.encode('base64').replace('\n', '')

def make_register_req(name, n):
	params = ','.join([b64(p) for p in [name, n]])
	req = ':'.join(['register', params])
	return req

def make_login_req(name, n, sig):
	sig = hex(sig)[2:].strip('L')
	sig = ('\0' + sig) if (len(sig) % 2 == 1) else sig
	print 'sig:', sig
	sig = sig.decode('hex')
	params = ','.join([b64(p) for p in [name, n, sig]])
	req = ':'.join(['login', params])
	return req

def snd_rcv(req):
	s = socket.socket()
	s.connect(addr)
	print '>', req
	s.send(req)
	resp = s.recv(4096).strip()
	print '<', resp
	return resp

resp1 = snd_rcv(make_register_req(name, n1))
sig1 = pow(int(resp1), d, base)
assert snd_rcv(make_login_req(name, n1, sig1)) == 'Hello ' + name

resp2 = snd_rcv(make_register_req(name, n2))
sig2 = pow(int(resp2), d, base)
assert snd_rcv(make_login_req(name, n2, sig2)) == 'Hello ' + name


r1 = sig1 / Q
r2 = sig2 / Q
assert r1 == r2

s1 = sig1 % Q
s2 = sig2 % Q
assert s1 != s2

ds = (s1 - s2) % Q
inv_ds = modinv(ds, Q)

h1 = h(makeMsg(name, n1))
h2 = h(makeMsg(name, n2))

dh = (h1 - h2) % Q
k = (dh * inv_ds) % Q
inv_r1 = modinv(r1, Q)
inv_r2 = modinv(r2, Q)

PRIVATE1 = ((s1 * k - h(makeMsg(name, n1))) * inv_r1) % Q
PRIVATE2 = ((s2 * k - h(makeMsg(name, n2))) * inv_r2) % Q
inv_k = modinv(k,Q)
assert PRIVATE1 == PRIVATE2
PRIVATE = PRIVATE1
assert PUBLIC == pow(G, PRIVATE, P)

def my_sign(name, n):
  k = 1
  r = pow(G, k, P) % Q
  s = (modinv(k, Q) * (h(makeMsg(name, n)) + PRIVATE * r)) % Q
  return (r*Q + s)

n = ''
name = 'admin'
print snd_rcv(make_login_req(name, n, my_sign(name, n))) 
