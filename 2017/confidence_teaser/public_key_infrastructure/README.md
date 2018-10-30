
# Public Key Infrastructure

This is a short writeup on solving the 'Public Key Infrastructure' challenge from the CONfidence teaser CTF by DragonSector.

## The Challenge

We are given an address of a service that runs some [code](task.py) written in python.

This code implements a service with two functionalities: `register` and `login` which maps to `sign` and `verify`.
The user may ask to sign any name except _admin_ and get some signature. Then, a user can ask to login, providing the username and a signature to get some response from the system.

From the code above, the objective of the challenge is to pass the `verify` function on the _admin_ name and thus get the flag from the `login` function.

## The Dawn Of DSA

Going over the code, this looks like some signing algorithm which signs/verifies user's messages. A quick search comes up with a very similar algorithm: [DSA](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm).

Comparing DSA outline in wikipedia and the challenges' code, we see the following differences/peculiarities:

* `r,s` in the signature mustn't be zero in DSA, yet in the challenge they might be
* `n`, which does not exist in DSA, is used in the **beginning** of strings in the `makeK` and `makeMsg` functions
* `k` must be **random** per message, however it's computed with a hash function (deterministic)
* the hash function used for computing k - md5 - is insecure
* the message can be signed locally (no nonce/salt in the username hash)
* the signature `(r,s)` is encoded as ${(s + r*Q)^e mod\ n}$ where $e = 2^{16} + 1$

## Things That Didn't Work

The first implementation mistake seems very promising. Since we provide the signature to verify, it is very easy to pass a signature such that `r == 0`. Working the equations in the `verify` process, we get that:
$$u2 \equiv r * w = 0$$
$$v \equiv (G^{u1} * PUBLIC^{u2}) mod\ P\ mod\ Q \equiv G^{u1} * 1 mod\ P\ mod\ Q$$
Which completely eliminates the public/private component in the system.

So, in order to solve the challenge, all we need is to find a $u1$ and an integer $\alpha$ such that $Q$ divides $g^{u1}-\alpha * P$ so the comparison of `v` and `r` holds true ($v = G^{u1}\ mod\ P\ mod\ Q \equiv 0 = r$).

Unfortunately, finding this value is computationaly **hard**. We suspect it is equivalent to the discrete logarithm problem. Just to make sure, we wrote a small brute-force and let it run, but it didn't return any results.

We also thought maybe put 'name: admin' as part of `n`, and trick the server to sign a request the will hold for `name = 'admin'`, but it was impossible.

## Back On Track

Looking at the other implementation problems, we started wondering what happens if we generate the same `k` for different messages. Some digging online resulted with a short blog describing a [very simple attack](https://rdist.root.org/2010/11/19/dsa-requirements-for-random-k-value/).
To implement this attack, we need the following:
* two messages - `m1,m2` such that `h(m1) != h(m2)` yet `k(m1) == k(m2)`
* getting the hash, `s` and `r` of each of the messages

If we have all that, we can compute k as following:
$$k = ({h(m1) - h(m2)) * (s(m1) - s(m2))^{-1}\ mod\ Q}$$
and than, get the private key from the following formula:
$$PRIVATE = ((s(m1) * k) - h(m1)) * r^{-1}\ mod\ Q$$

After getting the private key, we can sign any message (since we know how to generate the hash for a message).
Note that even though we don't get the SECRET using this message, it doesn't matter because the only requirement from K is to be random and it's generation method is not used anywhere in the original algorithm.

## Hashes In Colide

The first step in our plan is to create a hash collision on `k` for two different messages.
Looking at the code, we see:

```python
k = int(hashlib.md5('K = {n: ' + n + ', name: ' + name + ', secret: ' + SECRET + '}').hexdigest(), 16)
```
We have no limitiations on `n`, so we can genearate an MD5 collision on `'K = {n: ' + n ` using [fastcoll](https://github.com/upbit/clone-fastcoll). Due to the [Merkle-Damgard construction](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction) of MD5, if the prefixes collide, adding the same suffix to both messages will also result in collision. Thus, the `SECRET` and limitations on `name` don't really bother us.

## Getting The Signature

Here we find ourselves in an uncharted territory. The register function returns ${(s + r*Q)^e mod\ n}$ where $e = 2^{16} + 1$ and we need to get the original `s,r`.

The solution was quite ineteresting. We can extend `n` as much as we want. Padding `n` with `\x00` bytes is, in-fact, multiplying `n` by $256$.  We note that $x\ mod\ nm\ mod\ m \equiv x\ mod\ m$ for any $n,m$.
So we pad our collision with enough `\x00` that eventually $2^{320} = 16^{40}$ divides $n$ (why 320? because $Q$ is 160 bit, thus $s + r*Q$ is at most $160*2$ bit)

Then, we send a _register_ request with some name and our `n`. Now, denote $sig := s + r*Q$, so the result is $sig^{e} mod\ n$. According to the fact above follows: $sig^{e} mod\ n\ mod\ 2^{320} = sig^{e} mod\ 2^{320}$. We compute $d \equiv e^{-1} mod\ \varphi (2^{320})$ (therefore exists $t$ such that $e*d - 1 = t * \varphi(2^{320})$). According to [Euler's Theorem](https://en.wikipedia.org/wiki/Euler%27s_theorem) if $sig$ is odd ($sig,2^{320}$ are co-prime) then 
$$(sig^{e})^{d} \equiv sig^{e*d} \equiv sig * sig^{e*d - 1} \equiv sig * sig^{t * \varphi(2^{320})} \equiv sig * (sig^{\varphi(2^{320})})^t \equiv sig * 1^t \equiv sig $$.

And this is how we can extract the original $sig$.

If $sig$ is not odd, this fails miserably and $(sig^{e})^{d}$ will result in 0, giving us a good indication wether we extracted a valid signature or not.

## Executing The Attack

We take the hash collisions we found for the prefix 'K ={n: ' and extend it with 40 '\x00', denote it with `n1,n2`.
Then choose a `name` - 'a' and send _register_ requests to the server with `name` and `n1,n2` and exponentiate the response by $e^{-1}\ mod\ \varphi(2^{320})$ and save it as `sig1` and `sig2`.
If the responses are even, we try again with a different name.
We can verify we extracted the correct signatures by sending a _login_ request to the server with the signatures.
Then, we extract `r` and `s` for each signature and compute the hashes of the messages locally:
```python
r1, r2 = sig1 / Q, sig2 / Q ## in fact - the same value
s1, s2 = sig1 % Q, sig2 % Q
h1,h2 =  h(makeMsg(name, n1)), h(makeMsg(name, n2))
```
and then compute `k` and then the `PRIVATE` key:
```python
k = ((h1 - h2) * modinv(s1 - s2, Q)) % Q
PRIVATE = ((s1 * k - h(makeMsg(name, n1))) * modinv(r1, Q)) % Q
```
(the calculation of `PRIVATE` according to `n1` and `n2` are the same and correspond to the `PUBLIC` key)
Now, we can sign any name - including _admin_ :)
```python
n = '' ## doesn't matter
k = 1 ## doesn't matter
r = pow(G, k, P) % Q
s = (modinv(k, Q) * (h(makeMsg(name, n)) + PRIVATE * r)) % Q
admin_sig = r*Q + s
```

And that's it. We have a valid signature for `name = 'admin'` (with `n = ''`) and we can now login and get the flag.

You may find the full solution's code [here](solve.py).
