# HITCON CMT 17 - Prob Crypto Challenge

In the [challenge](prob.py) there is a service that communicates with a client in AES-CBC mode with standard PKCS#7 padding scheme. All messages are sent and received encrypted and we do not have the key.
However, we (as clients) do control the IV of the messages we send and the IV of the server remains constant (I think it is not crucial for solving this challenge though).
The service starts with sending a 'Welcome!!' message (encrypted) and waits for the client to send (encrypted) commands.
Although we do not have the key, we do control the IV. As the IV is xored with the message after the decryption (and before removing the padding), we can change the IV to send any message we want (as long as it's 15 bytes or shorter).
Here is the function for creating an `(IV,Cipher)` pair for certain message `msg_new`:
```python
def create_iv(msg, iv, msg_new):
    return xor(iv, pad(msg), pad(msg_new))

IV = create_iv('Welcome!!', iv_remote, 'get-flag')
Cipher = cipher_msg_welcome[:16]
```
The decryption of this pair is the `get-flag` command because the xoring with the IV is applied after decryption of the `cipher_msg_welcome[:16]` block.
The process is:
```
d0 = AES.decrypt(cipher_msg_welcome[:16])
d1 = d0 ^ IV
## which is equivalent to
d0 ^ iv_remote ^ pad('Welcome!!') ^ pad('get-flag')
## by creation of d0 and cipher_msg_welcome[:16] we know that
d0 ^ iv_remote == pad('Welcome!!')
## so we can assign it and get
pad('Welcome!!') ^ pad('Welcome!!') ^ pad('get-flag')
## which is equivalent to
pad('get-flag')
``` 
The service respond with an encryption message containing the flag.

Now we have the encrypted flag and we need to start finding the bytes of the flag denoted with `c_flag`, it is 2-blocks long (32 bytes).
We know from the service's source that the flag starts with `hitcon{`. Understanding  the padding scheme implementation, we can brute-force the last byte of the first block alone.
First, we send a message containing only the command `echo`. The service responds with encrypting the remaining part of the message, removing the `echo`.
```python
            elif msg.startswith('echo'):
                send_msg(msg[4:])
```
In this case, the respond is simply an encryption of and empty string denoted `c_empty`.
Next, we alter the `create_iv` function to allow forcing the `msg` last byte:
```python
def create_iv(msg, iv, msg_new, last_byte=-1):
    msg = pad(msg)
    if -1 != last_byte:
        msg = msg[:-1] + last_byte

   return xor(iv, msg, pad(msg_new))
```
and now we brute-force every possible last byte, sending:
```python
IV = create_iv('hitc', iv_remote, 'echo', last_byte)
Cipher = c_flag[:16]
```
when we hit the correct byte, the server response is identical to the empty response, because the decrypted last byte makes the `unpad` function remove exactly 12 bytes and the bytes that remain are the `echo` command.

After finding the last byte in the first block, we can brute-force the remaining bytes in the block on at a time. We create a message that start with the `echo` command and continues with the remaining known bytes of the flag plus the guessed byte. For example, if we know the flag starts with `hitcon{` and our guess is `0`, we send a message which is decrypted to `echoon{0`. The server response is the encryption of `on{0`. Next, we try to convert the flag's first block to the same message, sending `create_iv('hitcon{0', iv_remote, 'echoon{0' , last_byte)` as IV and `c_flag[:16]` as a cipher. If `0` is indeed the correct character, the service responds with the same cipher and we can check it by comparison to the cipher we received earlier.

Now that we found the first 16 bytes of the flag (15 bytes + last byte), we can't proceed with the same method as is. The decryption of the second block is xored with the cipher of the first block which we can't change in a predictable way. However, the `echo` command provides us with a very neat way to move the remaining parts of the flag to the first block.
By changing just the fist four bytes of the flag's IV to `echo`, the service responds with and encryption of the flag starting in the fourth byte (`flag[4:]`). 
Applying this method 3 times (note we know the first 12 bytes of the flag), we get the encryption of `flag[12:]` and we know the first 4 bytes of the clear-text (the last 4 bytes of the first block). So we can now use the same method we used on the first block to decrypt the next 12 bytes.

This is it, decrypting the next 12 bytes gives us the desired [flag](flag.txt).
You can find the full solution [here](ex.py)

	Many thank to @doronsobol who helped me clearing my head in unconventional hours
