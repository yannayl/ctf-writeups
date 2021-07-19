# I CANT BELIEVE ITS NOT CRYPTO

This write-up is written in agony. It's a cautionary tale. It's a therapeutic endeavor. Yes, it's a challenge solved a couple of hours after the CTF is ended.

## The challenge
The challenge is very weird. It defines an obscure algorithm that manipulates two lists in a loop until the lists contain a specific value. The user should provide two lists that will cause the algorithm to iterate at least 2000 times.
```python
def count(l1, l2):
    n = 0
    while l1 + l2 != [1, 0]:
        step(l1, l2)
        n += 1
    return n

if __name__ == "__main__":
    l1, l2 = read_lists()
    c = count(l1, l2)
    if c > 2000:
        print("You win")
        print(open("flag.txt").read())
    else:
        print("Too small :(")
        print(c)
```

The conditions for the lists are as follows:
1. The lists length must agree and not exceed 23
2. The first list may contain only binary digits (0,1)
3. The second list may contain only binary digits (0,1,2)

The conditions are enforced (correctly) by this code:
```python
def read_lists():
    l1 = [ord(c) % 2 for c in input("> ")]
    l2 = [ord(c) % 3 for c in input("> ")]
    assert len(l1) < 24, "too big"
    assert len(l1) == len(l2), "must be same size"
    return l1, l2
```

A single iteration of the loop is implemented by the following code:
```python
SBOX = {
    (0, 0): (0, 0),
    (0, 1): (1, 0),
    (0, 2): (0, 1),
    (1, 0): (1, 1),
    (1, 1): (0, 2),
    (1, 2): (1, 2),
}

def step(l1, l2):
    if l1[0] == 0:
        l1.pop(0)
    else:
        l2.insert(0, 1)
    l1.append(0)

    for i in range(len(l1)):
        l1[i], l2[i] = SBOX[l1[i], l2[i]]

    while l1[-1] == l2[-1] == 0:
        l1.pop()
        l2.pop()
```

This is all the code in the challenge.

## Bad Ideas
My initial thought was "this reminds me of the Collatz Conjecture but not quite". The conjecture also defines a simple `step` function and discusses the results of applying this function repeatedly to a natural number. 
The Collatz step function is:
```python
def step(n):
    if n % 2 == 0:
        return n // 2
    else:
        return n * 3 + 1
```
The conjecture states that if the step function is applied repeatedly to any natural number, it will eventually be 1.

However, I dismissed the idea quite quickly for two reasons:
1. The step function in the challenge deals with 2 objects, not 1
2. The Collatz step applies arithmetic operations whereas the challenge step applies some logical manipulation and permutation. 

Our following ideas were even worse.

First, we thought of brute force but quickly realized the input space is roughly 2**50 which is too large.

We examined the SBOX and realized it's a permutation with two fixed points and one cycle of length 4. This wasn't very helpful, but we understood that the application of the SBOX doesn't have a sink, it just cycles in some orbit. The only important manipulations are the `if` at the beginning and the `while` in the end, because they can change the length of the lists. These manipulations only apply to the edge of the lists.
Using this insight, we implemented a simple fuzzer and directed it to mostly manipulate the middle of the sequence and not so much the extremes. The intuition is that the algorithm is very sensitive in the edges of the sequences and not so much in the middle, so it's better to explore three.
This fuzzer yielded sequences that made 1350 steps. Not bad but not good enough.

Then, we tried to see what is the maximum number of steps with shorter lists, say length 5,6,7. We saw that the number of steps for inputs of these lengths behaves weird. Most of them are distributed normally in some range but there are few outliers which have much more steps. So our hope to randomize it somehow (by fuzzing or gradient descent of some sort) disappeared.

Another thing we noticed is that the input of length 5 which had the longest walk was not correlated in any way with the input of length 6. The longest walk starting from input of length 5 was not a sub-walk of the longest walk of input of length 6. So we eliminated the possibility to build the solution iteratively with some greedy algorithm or linear programming.

At this point, we were left with mostly nothing. We were tired. We tried to think of ways to find some recursive structure of the lists but failed. We weren't even sure why the author of the challenge thinks this process halts for every input. Why don't they fear it will encounter some loop and spiral forever. We just waited for the CTF to end.

## Round 2
This morning I woke up angry. I felt stupid. I felt like I missed something and that I should be able to solve this challenge. I went to a colleague and asked what he thinks. He is a crypto guy. He said something about shift registers and stuff I didn't understand. But he also talked about encoding polynomes in ternary bits and stuff like that. He also didn't know nothing about Collatz Conjecture, and I found myself referring to it again and again when we discussed the challenge.
At some point, it just hit me. The Collatz step has two options, one deals with **twos** (divide by 2) and the other with **threes** (multiply by 3) and it depends on the least significant bit of the value (the parity). Another striking similarity is that the halt condition of the loop is when the lists have the value `1`. I realized it's possible this is actually some encoding of the Collatz conjecture. Then another piece fell in place, if the lists indeed encode a natural number, the `while` loop removes leading zeros from a Little-Endian encode number is very sensible. The only thing that disturbed the theory was the `SBOX`. I had no idea what part it played in this guess.
At this point, I decided to defer the `SBOX` problem for later and make an experiment. I decided to try and decode the lists into a natural number and see if anything familiar shows up.

If my guess is correct, the first bit in the first list should be the parity bit of the encoded number. And because zeros in the end of the lists were removed, it was logical to assume it's some little endian encoding. Finally, because a bit pair has six options [(0,1)*(0,1,2)] it made sense to use radix 6. Here is the encoding function I came up with:
```python
def toNum(l1, l2):
    num = 0
    for i in range(len(l1)):
        digit = l1[i] + l2[i]*2
        num += digit * (6**i)
    return num
```

I tried some small input:
```python
nums = []
l1, l2 = [0,0,1], [0,0,0]
while l1 + l2 != [1, 0]:
    step(l1, l2)
    nums.append(toNum(l1, l2))
print(nums)
```

And the output is:
`[18, 9, 28, 14, 7, 22, 11, 34, 17, 52, 26, 13, 40, 20, 10, 5, 16, 8, 4, 2, 1]`

Lo and behold! It's a Collatz orbit. My assumption holds.
I have no idea how the SBOX fixes it all, but there is no doubt about it.

## Solution
Now it's time for googling. A quick search will give the number "93571393692802302" which is "less than 10**17" and has 2091 steps. Great.
The solution is then simple:
```python
num = 93571393692802302
l1 = []
l2 = []
while num > 0:
    digit = num % 6
    num //= 6
    l1.append(digit%2)
    l2.append(digit//2)
w1 = ''.join(chr(0x30+i) for i in l1)
w2 = ''.join(chr(0x30+i) for i in l2)

from pwn import *
r = remote('steps.2021.ctfcompetition.com', 1337)
context.log_level = 'debug'
r.sendlineafter('>', w1)
r.sendlineafter('>', w2)
r.interactive()
```

and the output:
```
[x] Opening connection to steps.2021.ctfcompetition.com on port 1337
[x] Opening connection to steps.2021.ctfcompetition.com on port 1337: Trying 34.77.82.54
[+] Opening connection to steps.2021.ctfcompetition.com on port 1337: Done
[DEBUG] Received 0x1e bytes:
    b'== proof-of-work: disabled ==\n'
[DEBUG] Received 0x2 bytes:
    b'> '
[DEBUG] Sent 0x17 bytes:
    b'0110010101100001001110\n'
[DEBUG] Received 0x2 bytes:
    b'> '
[DEBUG] Sent 0x17 bytes:
    b'0112011222222120011102\n'
[*] Switching to interactive mode
 [DEBUG] Received 0x8 bytes:
    b'You win\n'
You win
[DEBUG] Received 0x21 bytes:
    b'CTF{5t3p_by_st3p_I_m4k3_my_w4y}\n'
    b'\n'
CTF{5t3p_by_st3p_I_m4k3_my_w4y}
```

## Final Thoughts (for future self)
As a CTFer, intuition is the most important asset. Don't dismiss it too fast. Usually, there should be a solution to a CTF and guessing the right direction is not too hard. Maybe the details are surprising, but usually the initial hunch is a good guide. Don't give up too fast. Don't get demotivated because you have not figured up all the details. Sometimes, a leap of faith and intelligent guesses can get you the flag.
