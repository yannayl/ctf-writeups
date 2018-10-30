# Crypto Solution

This challenge was a huge fun.

We are receieved a source code of a service written in C, which sends us a flag encrypted with AES and let us do some operations. The purpose of the challenge is to decrypt the flag.

The program starts with generating 16 AES keys of 16 bytes long each and put them in a _keystore_ array of bytes. Each entry in the _keystore_ is 17 bytes long - 16 bytes for the key and 1 byte for the key length. Then, it loads the first key from the store to the `current_key` buffer and uses it to encrypt and send the flag.
From that point, we can do the following operations:
1. regenerate key - sending key _index_ and _length_, the code reads _length_ bytes from `/dev/urandom` to the key in the specified _index_ and sets it's length to be the specified _length_.
2. load key - copies a key from the specified _index_ in the key store to the beginning of the `curent_key` buffer according to the _length_ of the specified key.
3. load data - reads 16 bytes of data from the user and puts them in a buffer.
4. encrypt - encrypt the data buffer with the current key and sends it to the client.

The challenge is written in C which implies some low level vulnerability. We took a quick look and found a nice integer overflow. The code works with pointer's arithmetic to derive the offset of the entry in the _keystore_, by multiplying the _index_ specified by the user with 17 - which is easily overflown. However, the code **does check** the result is within the boundaries of the _keystore_. So our vulnerabiliy only lets us escape the entry alignment when accessing the _keystore_, but we can't write outside the buffer. Sending an _index_ which is a mutiple of the modular inverse of 17 under 2^32 will cause the multiplication to result with any value we want.

Now, applying our vulnerability to operation 1 and sending zero length enables us to write a zero byte to weherever we want within the _keystore_.
From here, our algorithm is simple. We regenerate the key in index 1 with sizes from 0 to 15 and each time fill the key with zeros. Then we load this key to the `current_key` and encrypt a plain text with the current key.
The result is that we have `AES(known_plain_text, '0' * len + original_key[len:])` for each length between zero and 15. We can now brute force the cipher text in reverse order and deduce the bytes of the original key one at a time.
Then, we decrypt the original flag with the key we have and we are done.

## Original Challenge

```C
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "aes.h"

#define MAX_KEY_LEN 16
#define KEY_SIZE_LEN 1
#define ENTRY_SIZE (MAX_KEY_LEN + KEY_SIZE_LEN)
#define NUM_KEYS 16
#define STORAGE_SIZE (ENTRY_SIZE * NUM_KEYS)
#define MASTER_KEY_INDEX 0
#define DATA_SIZE 16

uint8_t keys[STORAGE_SIZE];
uint8_t data[DATA_SIZE];
uint8_t current_key[MAX_KEY_LEN];

void regenerate_key(unsigned int index, unsigned int len) {
  unsigned int offset = index * ENTRY_SIZE;

  if (offset > STORAGE_SIZE - ENTRY_SIZE || len > MAX_KEY_LEN) {
    return;
  }

  int fd = open("/dev/urandom", O_RDONLY);
  read(fd, &keys[offset], len);
  close(fd);
  keys[offset + MAX_KEY_LEN] = len;
}

void load_key(unsigned int index) {
  unsigned int offset = index * ENTRY_SIZE;
  unsigned int key_len = keys[offset + MAX_KEY_LEN];
  if (offset > STORAGE_SIZE - ENTRY_SIZE || key_len > MAX_KEY_LEN) {
    return;
  }
  memcpy(current_key, &keys[offset], key_len);
}

void encrypt(void) {
	uint8_t data_out[DATA_SIZE];
	AES128_ECB_encrypt(data, current_key, data_out);
	write(1, data_out, 16);
}

void load_data(void) {
  int ret;
  
  ret=read(0, data, DATA_SIZE);
  if (ret < 1)
    exit(0);
}

int main(void) {
  int ret;
  int i;
  for (i = 0; i < NUM_KEYS; i++) {
    regenerate_key(i, MAX_KEY_LEN);
  }
  
  int fd = open("flag.txt", O_RDONLY);
  read(fd, data, DATA_SIZE);
  close(fd);
  
  load_key(MASTER_KEY_INDEX);
  encrypt();
  
  memset(data, 0, DATA_SIZE);
  regenerate_key(MASTER_KEY_INDEX, MAX_KEY_LEN);
  
  char cmd;
  unsigned int p1, p2;
  while(1) {
    ret = read(0, &cmd, 1);
    if (ret < 1)
      return 0;
    if (cmd == 'l') {
      load_data();
    } else if (cmd == 'e') {
      encrypt();
    } else if (cmd == 'r') {
      ret = read(0, &p1, sizeof(p1));
      if (ret < 1)
	return 0;
      ret=read(0, &p2, sizeof(p2));
      if (ret < 1)
	return 0;
      regenerate_key(p1, p2);
    } else if (cmd == 'k') {
      ret=read(0, &p1, sizeof(p1));
      if (ret < 1)
	return 0;
      load_key(p1);
    }
  }
}
```

To build the code add the following code as `aes.h` and compile with `-lcrypto` (tested on Ubuntu 16.04).
```C
#include <openssl/evp.h>
#include <stdint.h>

void AES128_ECB_encrypt(void *data, void *current_key, void *data_out) {
	unsigned int inlen = 16, outlen = 16;
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit(&ctx, EVP_aes_128_ecb(), current_key, NULL);
	EVP_EncryptUpdate(&ctx, data_out, &outlen, data, inlen);
}
```

## Solution
```Python
from pwn import *
from Crypto.Cipher import AES

#r = remote("enc-service.hackable.software", 1337)
r = process("./a.out")

inv = 4042322161
def offset(o):
    return (o * inv) % (2**32)

def set_key(off, length):
    r.send('r' + p32(off) + p32(length))

def load_key(off):
    r.send('k' + p32(off))

def enc(data):
    r.send('l' + data)
    r.send('e')
    return r.recvn(16)

enc_flag = r.recvn(16)

KPT = '\0' * 16
CPH = []

CPH.append(enc(KPT))

for i in xrange(16):
    set_key(1,i+1)
    for j in xrange(i+1):
        off = offset(j+1)
        set_key(off,0)
    load_key(1)
    CPH.append(enc(KPT))

for i,c in enumerate(CPH):
    print i, c.encode('hex')

print AES.new(KPT).encrypt(KPT) == CPH.pop()

key = ['\0'] * 16

for i, ct in enumerate(reversed(CPH)):
    for c in xrange(256):
        key[i] = chr(c)
        if AES.new(''.join(reversed(key))).encrypt(KPT) == ct:
            print "found", i, ":", hex(c)
            break

print "+" * 70
print AES.new(''.join(reversed(key))).decrypt(enc_flag)
print "+" * 70
```
