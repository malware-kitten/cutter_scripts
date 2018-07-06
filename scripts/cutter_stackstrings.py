#!/usr/bin/env python

import r2pipe
import json
import struct
import cutter
from pprint import pprint, pformat

####################################
# Cutter Stack Strings Tool
# Nick Hoffman @infoseckitten
####################################

def print_data(data,offset):
    cleaned = ""
    for c in data:
        if (ord(c) <= 0x7f and ord(c) >= 0x20) :
            cleaned+= c
    if len(cleaned) >= 3:
        print('%d - Hidden String: "%s"' % (offset, cleaned))
        cutter.cmd('CC Hidden String: \"%s\" @ %d' % (cleaned, offset))

def mov_obtain_constant(instr):
    retval = False
    #is the value explicitly called out?
    if 'val' in instr:
        retval = instr['val']
    #is this a memory reference?
    elif str(instr['esil'].split(',')[1]) == '[]':
        retval = False
    #manually extract from esil
    else:
        try:
            retval = int(instr['esil'].split(',')[0])
        except ValueError:
            retval = False
    if retval:
        #find the bit_length to correctly unpack
        bits = retval.bit_length()
        if bits <= 8:
            retval = struct.pack('<B', retval)
        if bits > 8 and bits <= 32:
            retval = struct.pack('<I', retval)
        if bits > 32 and bits <= 64:
            retval = struct.pack('<Q', retval)
    return retval

def mov_hunt(instructions):
    #instruction types to continue building our string
    continue_ops = ['mov','upush','push','lea','nop']
    #for now, ignore these instructions
    ignore_ops = ['upush','push','lea','nop']
    canidate = ""
    for instr in instructions['ops']:
        if instr['type'] in continue_ops:
            if instr['type'] in ignore_ops:
                continue
            val = mov_obtain_constant(instr)
            if val:
                canidate += val.decode('UTF-8','ignore')
            #hit a string terminator, print and clear
            if canidate.endswith('\x00'):
                print_data(canidate, instr['offset'])
                canidate = ""
        else:
            #another instruction type been encountered
            #string is no longer being built, print and clear
            if canidate:
                print_data(canidate, instr['offset'])
                canidate = ""

def radare_crawl():
    funcs = json.loads(cutter.cmd('aflj'))
    for func in funcs:
        try:
            instructions = json.loads(cutter.cmd('pdfj %s @ %s' % (func['size'],func['offset'])))
        except ValueError as e:
            continue
        mov_hunt(instructions)

cutter.cmd('aaa;aap')
radare_crawl()
cutter.refresh()
