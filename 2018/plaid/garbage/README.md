# PlaidCTF 2018: Garbage Truck Challenge 
 
We receive a [binary](./garbagetruck_04bfbdf89b37bf5ac5913a3426994185b4002d65) with a very obvious stack based buffer overflow bug. 
This is what the main loop function looks like: 
```C 
cnt = 0; 
while ( 1 ) { 
    printf("Pitch?\n> "); 
    in = read64(); 
    if ( !in ) 
        break; 
    if  (is_garbage(in)) { 
        puts("Throwing away that garbage!"); 
        idx = cnt++; 
        buf[idx] = in; 
    } else { 
        puts("That's not garbage. I love it <3"); 
    } 
} 
close(0); 
``` 
Where `buf` is a buffer on the stack. The binary is not `PIE`d and has no stack canaries. 
So, if the input number returned from the user in the `read64` function `is_garbage` then we get to write it to the stack. 
After some reversing, we see that the `is_garbage` function is actually the Rabin-Miller primality test which is implemneted in the statically linked `openssl` library contained in the binary. 
Therefore, the challenge is to write a ROP-chain which would print the flag using only prime 64-bit numbers. Another limitation this binary present is that when returning from the function, the `stdin` is closed, so apparently the author intended for this chain to run without any further input from the user. 
 
We fired up `ROPgadget` and printed all gadgets (using the `--all` flag) and filtered only the [gadgets which address is a prime number](primes.txt) (using a simple python script). 
Then, we started to build a ROP chain. 
 
The first chain we managed to build was `system("cat *")`. Building it wasn't easy, as we weren't sure which `libc` version is used on the server and computing the location of the `system` function dynamically wasn't an easy task either. We first built a chain that printed a few values from the `.got` section to identify the `libc` version (2.23 from Ubuntu 16.04) and then built a chain that read the value of `read` from the got, added the difference between `system` and `read` and eventually jumped to system. The good thing is that every number is a sum of just a few primes (Goldbach conjecture), so we can get from one number to another quite easily if we find a good addition primitive. We were amused to find that `"cat *"` is a prime number :) 
However, this chain didn't work on the server. Neither a chain of `system("echo 7")` nor any other `system` based chain we tried. We don't know why (it did work locally), but there could be a few reasons (e.g. the server sandbox doesn't allow `exec`ing). 
 
Our next attempt was to construct a general, unconstrained, Write-What-Where primitive to build an Open-Read-Write chain. We managed to construct this primitive, however, it was too long and building a chain using it exhausted the stack. 
 
Eventually, an idea popped in our mind. The use of file descriptors `0` and `1` for `stdin` and `stdout` is merely a convention. The kernel is not aware of this convention and doesn't have any special handling for it. It is very much possible to switch the two or not use them at all. In our binary, even though file descriptor zero is closed before executing our ROP-chain, file descriptor 1 is untouched. If both file descriptors use the same underlying file - e.g. the socket of the connection with the user - reading from file descriptor 1 will read from the socket! 
A very common way to leverage a constrained ROP-chain to an unconstrained is to read from the user to the stack, i.e. `read(0, $rsp, 0x1000)`, which launches a second, unconstrained, chain.
Combining these two realizations, we constructed a chain that effectively `read(1, $rsp, 499)` and after that sent the address of some write from the binary. We received the output, so our conjecture turned out to be true - reading from file descriptor 1 works and reads from the connection. (We have a feeling that this hack wasn't intended though)

So, using this, we constructed a second ROP-chain with [all gadgets](gadgets.txt) in the binary. The second chain opens the flag file, reads it and writes it to the user.

You can find the full solution [here](ex.py). If you are interested in our false attempts, see the previous commits in this repository.
