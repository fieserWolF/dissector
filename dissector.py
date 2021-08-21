#!/usr/bin/env python3

"""
dissector v1.00 [21.08.2021] *** by fieserWolF
usage: dissector.py [-h] [-lf LABEL_FILE] [-o OFFSET] [-l LIMIT] [-t {acme,kickass}] [-d] [-i] [-ll] [-cc] input_file output_file startaddress

This program disassembles 6502 code.

positional arguments:
  input_file            binary input file
  output_file           sourcecode output file
  startaddress          startaddress in hex

optional arguments:
  -h, --help            show this help message and exit
  -lf LABEL_FILE, --label-file LABEL_FILE
                        labels json-file, default="c64labels.json"
  -o OFFSET, --offset OFFSET
                        offset in hex
  -l LIMIT, --limit LIMIT
                        limit in hex
  -t {acme,kickass}, --asmtype {acme,kickass}
                        assembler-type
  -d, --dump            show memory-dump
  -i, --illegals        use illegal opcodes
  -ll, --labels         show label-list
  -cc, --cycles         show cycles

Example: ./dissector.py test.prg test.a 2000 -lf c64labels.json -o 2 -l 100 -t acme --dump --labels --illegals --cycles
"""

import sys
import struct
import json
import argparse



PROGNAME = 'dissector';
VERSION = '1.00';
DATUM = '21.08.2021';

MAX_LABEL_TYPES = 20

ASM_STRING = {
    "acme": {
        "comment":";",
        "label":"",
        "byte":"!byte"
    },
    
    "kickass": {
        "comment":"//",
        "label":":",
        "byte":".byte"
    }
}


#http://www.oxyron.de/html/opcodes02.html

MODE = (    #string (not really necessary), length, label_possible
    {'name':'none', 'length': 1, 'label_possible': False},                    #0
    {'name':'imm = #$00', 'length': 2, 'label_possible': False},              #1
    {'name':'zp = $00', 'length': 2, 'label_possible': True},                 #2
    {'name':'zpx = $00,X', 'length': 2, 'label_possible': True},              #3
    {'name':'zpy = $00,Y', 'length': 2, 'label_possible': True},              #4
    {'name':'izx = ($00,X)', 'length': 2, 'label_possible': True},            #5
    {'name':'izy = ($00),Y', 'length': 2, 'label_possible': True},            #6
    {'name':'abs = $0000', 'length': 3, 'label_possible': True},              #7
    {'name':'abx = $0000,X', 'length': 3, 'label_possible': True},            #8
    {'name':'aby = $0000,Y', 'length': 3, 'label_possible': True},            #9
    {'name':'ind = ($0000}', 'length': 3, 'label_possible': True},            #10
    {'name':'rel = $0000 (PC-relative}', 'length': 3, 'label_possible': True} #11
)


OPCODE = (
    #types:
    #0 = normal opcode
    #1 = jsr
    #2 = jump
    #3 = brk/rts/rti
    #4 = illegal opcode
    #5 = branch
    #6 = load
    #7 = store
    {'name':'adc', 'type':6},    #0
    {'name':'and', 'type':6},    #1
    {'name':'asl', 'type':7},    #2
    {'name':'bcc', 'type':5},    #3
    {'name':'bcs', 'type':5},    #4
    {'name':'beq', 'type':5},    #5
    {'name':'bit', 'type':6},    #6
    {'name':'bmi', 'type':5},    #7
    {'name':'bne', 'type':5},    #8
    {'name':'bpl', 'type':5},    #9
    {'name':'brk', 'type':3},    #10
    {'name':'bvc', 'type':5},    #11
    {'name':'bvs', 'type':5},    #12
    {'name':'clc', 'type':0},    #13
    {'name':'cld', 'type':0},    #14
    {'name':'cli', 'type':0},    #15
    {'name':'clv', 'type':0},    #16
    {'name':'cmp', 'type':6},    #17
    {'name':'cpx', 'type':6},    #18
    {'name':'cpy', 'type':6},    #19
    {'name':'dec', 'type':7},    #20
    {'name':'dex', 'type':7},    #21
    {'name':'dey', 'type':7},    #22
    {'name':'eor', 'type':6},    #23
    {'name':'inc', 'type':7},    #24
    {'name':'inx', 'type':7},    #25
    {'name':'iny', 'type':7},    #26
    {'name':'jmp', 'type':2},    #27
    {'name':'jsr', 'type':1},    #28
    {'name':'lda', 'type':6},    #29
    {'name':'ldx', 'type':6},    #30
    {'name':'ldy', 'type':6},    #31
    {'name':'lsr', 'type':7},    #32
    {'name':'nop', 'type':0},    #33
    {'name':'ora', 'type':6},    #34
    {'name':'pha', 'type':0},    #35
    {'name':'php', 'type':0},    #36
    {'name':'pla', 'type':0},    #37
    {'name':'plp', 'type':0},    #38
    {'name':'rol', 'type':7},    #39
    {'name':'ror', 'type':7},    #40
    {'name':'rti', 'type':3},    #41
    {'name':'rts', 'type':3},    #42
    {'name':'sbc', 'type':6},    #43
    {'name':'sec', 'type':0},    #44
    {'name':'sed', 'type':0},    #45
    {'name':'sei', 'type':0},    #46
    {'name':'sta', 'type':7},    #47
    {'name':'stx', 'type':7},    #48
    {'name':'sty', 'type':7},    #49
    {'name':'tax', 'type':0},    #50
    {'name':'tay', 'type':0},    #51
    {'name':'tsx', 'type':0},    #52
    {'name':'txa', 'type':0},    #53
    {'name':'txs', 'type':0},    #54
    {'name':'tya', 'type':0},    #55
    {'name':'slo', 'type':4},    #56
    {'name':'rla', 'type':4},    #57
    {'name':'sre', 'type':4},    #58
    {'name':'rra', 'type':4},    #59
    {'name':'sax', 'type':4},    #60
    {'name':'lax', 'type':4},    #61
    {'name':'dcp', 'type':4},    #62
    {'name':'isc', 'type':4},    #63
    {'name':'kil', 'type':4},    #64
    {'name':'anc', 'type':4},    #65
    {'name':'alr', 'type':4},    #66
    {'name':'arr', 'type':4},    #67
    {'name':'xaa', 'type':4},    #68
    {'name':'axs', 'type':4},    #69
    {'name':'sbc', 'type':4},    #70
    {'name':'ahx', 'type':4},    #71
    {'name':'shy', 'type':4},    #72
    {'name':'shx', 'type':4},    #73
    {'name':'tas', 'type':4},    #74
    {'name':'las', 'type':4}     #75
)


CODE = (    # OPCODE, MODE, CYCLE, CYCLE_ADD_IF_BOUNDARY_CROSSED
    (10,0,7,0), #$00
    (34,5,6,0), #$01
    (64,0,0,0), #$02
    (56,5,8,0), #$03
    (33,2,3,0), #$04
    (34,2,3,0), #$05
    (2,2,5,0),  #$06
    (56,2,5,0), #$07
    (36,0,3,0), #$08
    (34,1,2,0), #$09
    (2,0,2,0),  #$0a
    (65,1,2,0), #$0b
    (33,7,4,0), #$0c
    (34,7,4,0), #$0d
    (2,7,6,0),  #$0e
    (56,7,6,0), #$0f
    (9,11,2,1), #$10    ###
    (34,6,5,1), #$11
    (64,0,0,0), #$12
    (56,6,8,0), #$13
    (33,3,4,0), #$14
    (34,3,4,0), #$15
    (2,3,6,0),  #$16
    (56,3,6,0), #$17
    (13,0,2,0), #$18
    (34,9,4,1), #$19
    (33,0,2,0), #$1a
    (56,9,7,0), #$1b
    (33,8,4,1), #$1c
    (34,8,4,1), #$1d
    (2,8,7,0),  #$1e
    (56,8,7,0), #$1f
    (28,7,6,0), #$20    ###
    (1,5,6,0),  #$21
    (64,0,0,0), #$22
    (57,5,8,0), #$23
    (6,2,3,0),  #$24
    (1,2,3,0),  #$25
    (39,2,5,0), #$26
    (57,2,5,0), #$27
    (38,0,4,0), #$28
    (1,1,2,0),  #$29
    (39,0,2,0), #$2a
    (65,1,2,0), #$2b
    (6,7,4,0),  #$2c
    (1,7,4,0),  #$2d
    (39,7,6,0), #$2e
    (57,7,6,0), #$2f
    (7,11,2,1), #$30    ###
    (1,6,5,1),  #$31
    (64,0,0,0), #$32
    (57,6,8,0), #$33
    (33,3,4,0), #$34
    (1,3,4,0),  #$35
    (39,3,6,0), #$36
    (57,3,6,0), #$37
    (44,0,2,0), #$38
    (1,9,4,1),  #$39
    (33,0,2,0), #$3a
    (57,9,7,0), #$3b
    (33,8,4,1), #$3c
    (1,8,4,1),  #$3d
    (39,8,7,0), #$3e
    (57,8,7,0), #$3f
    (41,0,6,0), #$40    ###
    (23,5,6,0), #$41
    (64,0,0,0), #$42
    (58,5,8,0), #$43
    (33,2,3,0), #$44
    (23,2,3,0), #$45
    (32,2,5,0), #$46
    (58,2,5,0), #$47
    (35,0,3,0), #$48
    (23,1,2,0), #$49
    (32,0,2,0), #$4a
    (66,1,2,0), #$4b
    (27,7,3,0), #$4c
    (23,7,4,0), #$4d
    (32,7,6,0), #$4e
    (58,7,6,0), #$4f
    (11,11,2,1), #$50   ###
    (23,6,5,1), #$51
    (64,0,0,0), #$52
    (58,6,8,0), #$53
    (33,3,4,0), #$54
    (23,3,4,0), #$55
    (32,3,6,0), #$56
    (58,3,6,0), #$57
    (15,0,2,0), #$58
    (23,9,4,1), #$59
    (33,0,2,0), #$5a
    (58,9,7,0), #$5b
    (33,8,4,1), #$5c
    (23,8,4,1), #$5d
    (32,8,7,0), #$5e
    (58,8,7,0), #$5f
    (42,0,6,0), #$60    ###
    (0,5,6,0),  #$61
    (64,0,0,0), #$62
    (59,5,8,0), #$63
    (33,2,3,0), #$64
    (0,2,3,0),  #$65
    (40,2,5,0), #$66
    (59,2,5,0), #$67
    (37,0,4,0), #$68
    (0,1,2,0),  #$69
    (40,0,2,0), #$6a
    (67,1,2,0), #$6b
    (27,10,5,0), #$6c
    (0,7,4,0),  #$6d
    (40,7,6,0), #$6e
    (59,7,6,0), #$6f
    (12,11,2,1), #$70   ###
    (0,6,5,1),  #$71
    (64,0,0,0), #$72
    (59,6,8,0), #$73
    (33,3,4,0), #$74
    (0,3,4,0),  #$75
    (40,3,6,0), #$76
    (59,3,6,0), #$77
    (46,0,2,0), #$78
    (0,9,4,1),  #$79
    (33,0,2,0), #$7a
    (59,9,7,0), #$7b
    (33,8,4,1), #$7c
    (0,8,4,1),  #$7d
    (40,8,7,0), #$7e
    (59,8,7,0), #$7f
    (33,1,2,0), #$80    ###
    (47,5,6,0), #$81
    (33,1,2,0), #$82
    (60,5,6,0), #$83
    (49,2,3,0), #$84
    (47,2,3,0), #$85
    (48,2,3,0), #$86
    (60,2,3,0), #$87
    (22,0,2,0), #$88
    (33,1,2,0), #$89
    (53,0,2,0), #$8a
    (68,1,2,0), #$8b
    (49,7,4,0), #$8c
    (47,7,4,0), #$8d
    (48,7,4,0), #$8e
    (60,7,4,0), #$8f
    (3,11,2,1), #$90    ###
    (47,6,6,0), #$91
    (64,0,0,0), #$92
    (71,6,6,0), #$93
    (49,3,4,0), #$94
    (47,3,4,0), #$95
    (48,4,4,0), #$96
    (60,4,4,0), #$97
    (55,0,2,0), #$98
    (47,9,5,0), #$99
    (54,0,2,0), #$9a
    (74,9,5,0), #$9b
    (72,8,5,0), #$9c
    (47,8,5,0), #$9d
    (73,9,5,0), #$9e
    (71,9,5,0), #$9f
    (31,1,2,0), #$a0    ###
    (29,5,6,0), #$a1
    (30,1,2,0), #$a2
    (61,5,6,0), #$a3
    (31,2,3,0), #$a4
    (29,2,3,0), #$a5
    (30,2,3,0), #$a6
    (61,2,3,0), #$a7
    (51,0,2,0), #$a8
    (29,1,2,0), #$a9
    (50,0,2,0), #$aa
    (61,1,2,0), #$ab
    (31,7,4,0), #$ac
    (29,7,4,0), #$ad
    (30,7,4,0), #$ae
    (61,7,4,0), #$af
    (4,11,2,1), #$b0    ###
    (29,6,5,1), #$b1
    (64,0,0,0), #$b2
    (61,6,5,1), #$b3
    (31,3,4,0), #$b4
    (29,3,4,0), #$b5
    (30,4,4,0), #$b6
    (61,4,4,0), #$b7
    (16,0,2,0), #$b8
    (29,9,4,1), #$b9
    (52,0,2,0), #$ba
    (75,9,4,1), #$bb
    (31,8,4,1), #$bc
    (29,8,4,1), #$bd
    (30,9,4,1), #$be
    (61,9,4,1), #$bf
    (19,1,2,0), #$c0    ###
    (17,5,6,0), #$c1
    (33,1,2,0), #$c2
    (62,5,8,0), #$c3
    (19,2,3,0), #$c4
    (17,2,3,0), #$c5
    (20,2,5,0), #$c6
    (62,2,5,0), #$c7
    (26,0,2,0), #$c8
    (17,1,2,0), #$c9
    (21,0,2,0), #$ca
    (69,1,2,0), #$cb
    (19,7,4,0), #$cc
    (17,7,4,0), #$cd
    (20,7,6,0), #$ce
    (62,7,6,0), #$cf
    (8,11,2,1), #$d0    ###
    (17,6,5,1), #$d1
    (64,0,0,0), #$d2
    (62,6,8,0), #$d3
    (33,3,4,0), #$d4
    (17,3,4,0), #$d5
    (20,3,6,0), #$d6
    (62,3,6,0), #$d7
    (14,0,2,0), #$d8
    (17,9,4,1), #$d9
    (33,0,2,0), #$da
    (62,9,7,0), #$db
    (33,8,4,1), #$dc
    (17,8,4,1), #$dd
    (20,8,7,0), #$de
    (62,8,7,0), #$df
    (18,1,2,0), #$e0    ###
    (43,5,6,0), #$e1
    (33,1,2,0), #$e2
    (63,5,8,0), #$e3
    (18,2,3,0), #$e4
    (43,2,3,0), #$e5
    (24,2,5,0), #$e6
    (63,2,5,0), #$e7
    (25,0,2,0), #$e8
    (43,1,2,0), #$e9
    (33,0,2,0), #$ea
    (43,1,2,0), #$eb
    (18,7,4,0), #$ec
    (43,7,4,0), #$ed
    (24,7,6,0), #$ee
    (63,7,6,0), #$ef
    (5,11,2,1), #$f0    ###
    (43,6,5,1), #$f1
    (64,0,0,0), #$f2
    (63,6,8,0), #$f3
    (33,3,4,0), #$f4
    (43,3,4,0), #$f5
    (24,3,6,0), #$f6
    (63,3,6,0), #$f7
    (45,0,2,0), #$f8
    (43,9,4,1), #$f9
    (33,0,2,0), #$fa
    (63,9,7,0), #$fb
    (33,8,4,1), #$fc
    (43,8,4,1), #$fd
    (24,8,7,0), #$fe
    (63,8,7,0)  #$ff
)


#my_label = [ [0] *2 for i in range(16) ]    #32 bytes multidimensional list

output = []
string_comment = ASM_STRING['acme']['comment']
string_label = ASM_STRING['acme']['label']





def _write_header (
    PROGNAME,
    VERSION,
    DATUM,
    filename_in,
    my_address,
    my_offset,
    my_limit
) :
    global string_comment
    global output
    output.append('%s Source generated by %s v%s [%s] *** by fieserWolF\n' % (string_comment, PROGNAME, VERSION, DATUM))
    output.append('%s FILENAME: %s, address: $%04x, offset: $%04x, length: $%04x\n' %(string_comment, filename_in,my_address,my_offset,my_limit))
    output.append('%s---------------------------------------------------------------------------\n' %(string_comment))
    output.append('\n')
    return None



def _write_memory_dump (
    buffer,
    my_address
) :
    global output
    output.append('memory:\n\n')
    count = 0
    for data in buffer :
        if ((count % 16)==0) : output.append('$%04x ' % (count+my_address))
        if ((count % 8)==0) : output.append(' ')
        output.append('%02x ' % (data))
        if (((count+1) % 16)==0) : output.append('\n')
        count += 1
    output.append('\n')
    output.append('\n')
    output.append('\n')
    output.append('\n')
    output.append('\n')
    return None




def _write_disassembly (
    disassembly,
    my_address,
    user_asm_type,
    user_show_cycles,
    user_illegals,
    labels
) :
    global string_comment, string_label, output
    
    if (user_illegals) :
        print('    Using illegal opcodes...')
    
    CYCLES_PLUS_STRING = ['','+']
    output.append('disassembly:\n\n')



    # start address entry point
    output.append('\t\t\t* = $%04x\n\n' %(my_address))


    for data in disassembly :
        
        #prepare address
        my_address = '$%04x\t' % data['pos']

        #prepare memory data
        my_memory = ''
        my_memory_byte = ''
        if (data['length'] == 1) : 
            my_memory = '%02x\t\t\t' % (data['value0'])
            my_memory_byte = '$%02x' % (data['value0'])
        if (data['length'] == 2) : 
            my_memory = '%02x %02x\t\t' % (data['value0'], data['value1'])
            my_memory_byte = '$%02x,$%02x' % (data['value0'], data['value1'])
        if (data['length'] == 3) : 
            my_memory = '%02x %02x %02x\t' % (data['value0'], data['value1'], data['value2'])
            my_memory_byte = '$%02x,$%02x,$%02x' % (data['value0'], data['value1'], data['value2'])

        address_and_memory = my_address + my_memory

    

        #write own labels
        for my_label in labels :
            if (my_label['address']-my_label['add'] == data['pos']) :
                output.append('%s%s\n' % (my_label['name'], string_label))
        

       
        #write opcode
        target = data['target_address']
        label_set = False
        for my_label in labels :
#            if ((my_label['address'] == target) & (my_label['type'] == 0)) :    #only use internal labels
            if (
                (my_label['address'] == target) &
                #(data['mode'] != 1)                   # do not replace imm = #$00 with label
                (data['label_possible'] == True)                   # do not replace imm = #$00 with label
            ) :
                target = my_label['name']
                label_comment = my_label['comment']
                if (my_label['add'] > 0) : target = target+ '+' +str(my_label['add'])
                label_set = True



        #if (isinstance(target,str) == True) :
        #    print('target is a string!')



        my_line = '\t\t\t'

        # deal with illegal opcodes:
        if (
            (data['opcode_type'] == 4) & # illegal
            (user_illegals == False)
        ) :
            my_line += string_byte + ' ' + my_memory_byte
                
                
        else :
            #write opcode
            if (data['mode'] == 0)  : my_line += ('%s' % (data['opcode']))                               #    ('none', 1),                     #0
            if (data['mode'] == 1)  : my_line += ('%s #$%02x' % (data['opcode'],target))     #    ('imm = #$00', 2),               #1



            #now, this is ugly...
            if (label_set == True) :
                if (data['mode'] == 2)  : my_line += ('%s %s' % (data['opcode'],target))    #    ('zp = $00', 2),                 #2
                if (data['mode'] == 3)  : my_line += ('%s %s,x' % (data['opcode'],target))    #    ('zpx = $00,X', 2),              #3
                if (data['mode'] == 4)  : my_line += ('%s %s,y' % (data['opcode'],target))    #    ('zpy = $00,Y', 2),              #4
                if (data['mode'] == 5)  : my_line += ('%s (%s,x)' % (data['opcode'],target))  #    ('izx = ($00,X)', 2),            #5
                if (data['mode'] == 6)  : my_line += ('%s (%s,y)' % (data['opcode'],target))  #    ('izy = ($00,Y)', 2),            #6
                if (data['mode'] == 7)  : my_line += ('%s %s' % (data['opcode'],target))      #    ('abs = $0000', 3),              #7
                if (data['mode'] == 8)  : my_line += ('%s %s,x' % (data['opcode'],target))    #    ('abx = $0000,X', 3),            #8
                if (data['mode'] == 9)  : my_line += ('%s %s,y' % (data['opcode'],target))    #    ('aby = $0000,Y', 3),            #9
                if (data['mode'] == 10) : my_line += ('%s (%s)' % (data['opcode'],target))    #    ('ind = ($0000)', 3),            #10
                if (data['mode'] == 11) : my_line += ('%s %s' % (data['opcode'],target))      #    ('rel = $0000 (PC-relative)', 3) #11
            else :
                if (data['mode'] == 2)  : my_line += ('%s $%02x' % (data['opcode'],target))    #    ('zp = $00', 2),                 #2
                if (data['mode'] == 3)  : my_line += ('%s $%02x,x' % (data['opcode'],target))    #    ('zpx = $00,X', 2),              #3
                if (data['mode'] == 4)  : my_line += ('%s $%02x,y' % (data['opcode'],target))    #    ('zpy = $00,Y', 2),              #4
                if (data['mode'] == 5)  : my_line += ('%s ($%02x,x)' % (data['opcode'],target))  #    ('izx = ($00,X)', 2),            #5
                if (data['mode'] == 6)  : my_line += ('%s ($%02x,y)' % (data['opcode'],target))  #    ('izy = ($00,Y)', 2),            #6
                if (data['mode'] == 7)  : my_line += ('%s $%04x' % (data['opcode'],target))      #    ('abs = $0000', 3),              #7
                if (data['mode'] == 8)  : my_line += ('%s $%04x,x' % (data['opcode'],target))    #    ('abx = $0000,X', 3),            #8
                if (data['mode'] == 9)  : my_line += ('%s $%04x,y' % (data['opcode'],target))    #    ('aby = $0000,Y', 3),            #9
                if (data['mode'] == 10) : my_line += ('%s ($%04x)' % (data['opcode'],target))    #    ('ind = ($0000)', 3),            #10
                if (data['mode'] == 11) : my_line += ('%s $%04x' % (data['opcode'],target))      #    ('rel = $0000 (PC-relative)', 3) #11



        #write comments
        if (len(my_line) <= 6)  : my_line += '\t'
        if (len(my_line) <= 10)  : my_line += '\t'
        if (len(my_line) <= 14)  : my_line += '\t'
        if (len(my_line) <= 18)  : my_line += '\t'
        if (len(my_line) <= 22)  : my_line += '\t'
        if (len(my_line) <= 26)  : my_line += '\t'
        my_line += ('%s' % string_comment)


        #show memory dump
        for my_data in address_and_memory :
            my_line += my_data



        if (user_show_cycles == True) :
            my_line += ('%d%scycles ' % (
                    data['cycles'],
                    CYCLES_PLUS_STRING[data['cycles_plus']]
                )
            )
        
        if (data['opcode_type'] == 1) : #jsr
            my_line += 'jump to & return from'
            if (label_set == True) : my_line += (' $%04x [%s]\n' % (data['target_address'], label_comment))
            else: my_line += '\n'

        if (data['opcode_type'] == 2) : #jump
            my_line += 'jump'
            if (label_set == True) : my_line += (' to $%04x [%s]\n' % (data['target_address'], label_comment))
            else: my_line += '\n'
            my_line += ('%s------------------------------------\n' %(string_comment))

        if (data['opcode_type'] == 3) :    # rts/rti
            my_line += ('\n')
            my_line += ('%s------------------------------------\n' %(string_comment))

        if (data['opcode_type'] == 4) : # illegal
            my_line += ('illegal opcode [$%02x]'% (data['value0']))

        if (data['opcode_type'] == 5) : #bne
            my_line += ('conditional branch')
            if (label_set == True) : my_line += (' to $%04x [%s]\n' % (data['target_address'], label_comment))
            else: my_line += ('\n')

        if (data['opcode_type'] == 6) : #load
            if (label_set == True) : my_line += ('load from $%04x [%s]' % (data['target_address'], label_comment))

        if (data['opcode_type'] == 7) : #store
            if (label_set == True) : my_line += ('store at $%04x [%s]' % (data['target_address'], label_comment))


        my_line += ('\n')
        
        output.append(my_line)

    return None



def _write_labels (
    labels
) :
    global string_comment, string_label


    # write labels
    output.append('\n')
    output.append('\n')
    output.append('\n')
    output.append('\n')
    output.append('\n')
    output.append('labels:\n\n')
    #for a in range(0,len(label_def)) :
    for a in range(0,5) :
        for data in labels :
            if (data['type'] == a) :
                output.append("%s\t= " % data['name'])    #name
                output.append("$%04x\t" % data['address']) #address
                output.append('%s' % string_comment)
                output.append("%s" % data['comment']) #comment
                output.append("\n")



    output.append('\n')
    return None


def _read_file(
    filename_in,
    my_offset,
    my_limit
) :
	#open input file
    print ("    Opening file \"%s\" for reading..." % filename_in)
    try:
        file_in = open(filename_in , "rb")
    except IOError as err:
        print("I/O error: {0}".format(err))
        sys.exit(1)

    # read file into buffer
    buffer=[]
    count = 0
    while True :
        data = file_in.read(1)  #read 1 byte
        if not data: break
        if ( count >= my_offset) :
            temp = struct.unpack('B',data)
            buffer.append(temp[0])
            if (
                (my_limit != 0) &
                (len(buffer) >= my_limit)
            ) : break
        count += 1

    file_in.close()

    return buffer



def _save_file(
    filename_out
) :
    global output
    
    # write file
    print ("    Opening file \"%s\" for writing..." % filename_out)
    try:
        file_out = open(filename_out , "w")
    except IOError as err:
        print("I/O error: {0}".format(err))
        sys.exit(1)

    for data in output : file_out.write(data)
    file_out.close()
    return None



def _create_disassembly(
    buffer,
    my_address
) :
    global CODE, MODE, OPCODE
    
    disassembly = []
    pos = 0
    flag_continue = True
    while flag_continue :
        if ((pos+0) < len(buffer)) : my_value0 = buffer[pos+0]
        else: break
        if ((pos+1) < len(buffer)) : my_value1 = buffer[pos+1]
        else:
            my_value1 = 0
            flag_continue = False
        if ((pos+2) < len(buffer)) : my_value2 = buffer[pos+2]
        else:
            my_value2 = 0
            flag_continue = False


       
        my_opcode_number = CODE[my_value0][0]
        my_opcode = OPCODE[ my_opcode_number ]['name']
        my_opcode_type = OPCODE[ my_opcode_number ]['type']
        my_mode =   CODE[my_value0][1]
        my_length =         MODE[   CODE[my_value0][1] ]['length']
        my_label_possible = MODE[   CODE[my_value0][1] ]['label_possible']
        my_cycles =          CODE[my_value0][2]
        my_cycles_plus =     CODE[my_value0][3]


        # deal with 8 or 16 bit addresses
        if (my_length == 3) : target_address = (my_value2 << 8)+my_value1
        else : target_address = my_value1

        #deal with branches
        #if (my_opcode_type == 1) :
        if (my_mode == 11) :    #relative PC
            my_mode = 7 #absolute = $0000
            if (my_value1 >= 128) : target_address = pos+my_address+2-(256-my_value1)
            else : target_address = pos+my_address+2+my_value1
            my_length = 2

        tmp_data = {
            "pos" : pos+my_address,
            "value0" : my_value0,
            "value1" : my_value1,
            "value2" : my_value2,
            "length" : my_length,
            "target_address" : target_address,
            "opcode_number" : my_opcode_number,
            "opcode" : my_opcode,
            "opcode_type" : my_opcode_type,
            "mode" : my_mode,
            "label_possible" : my_label_possible,
            "length" : my_length,
            "cycles" : my_cycles,
            "cycles_plus" : my_cycles_plus
        }
        disassembly.append(tmp_data)

        pos += my_length
        
    return disassembly





def _create_labels (
    disassembly,
    filename_labels,
    my_address,
    my_limit
):
    global MAX_LABEL_TYPES
    
	#open labels file
    print ("    Opening labels-file \"%s\" for reading..." % filename_labels)
    try:
        file_labels = open(filename_labels , "rb")
    except IOError as err:
        print("I/O error: {0}".format(err))
        sys.exit(1)
    user_labels = json.load(file_labels)
    file_labels.close()

    # append user program area to labellist
    tmp_code = {
        "from": my_address,
        "to": my_address+my_limit-1,
        "type": "",
        "area": "code",
        "area_type": 0,
        "short": "",
        "comment": "user program"
    }
    user_labels.append(tmp_code)
#    print(user_labels[len(user_labels)-1])


    my_label = []
    label_counter = [0] * MAX_LABEL_TYPES
    for data in disassembly :
        if (
            #(data['length'] == 3) |  #add label if opcode is followed by a 16bit address
            #(data['mode'] == 7)  #or a branch
            (data['label_possible'] == True)
        ):  
#            for this_def in label_def :
            for this_def in user_labels :
                #do we find this location in any label_def?
#                if ( (data['target_address'] >= this_def['min_address']) & (data['target_address'] <= this_def['max_address']) ) :
                if ( (data['target_address'] >= this_def['from']) & (data['target_address'] <= this_def['to']) ) :
                    #we found it in this list
                    
                    #check if we already have this label in our list
                    duplicate = False
                    for check in my_label :
                        if (check['address'] == data['target_address']) : duplicate = True; break   #duplicate
                        #if (check['address']+check['add'] == data['target_address']) : duplicate = True; break   #duplicate
                    if (duplicate == True) : break
                    
                    #this label is a new one
                    label_name = str(this_def['area']) + '_'
                    if (this_def['short'] != '') :
                        label_name = label_name + str(this_def['short']) + '_'
                    label_name = label_name + str(label_counter[this_def['area_type']]).zfill(3)
                    
                    #do we find it in memory address or do we have to add +1 or +2 ?
                    add_me = 0
                    #if (this_def['type'] == 0) :    # only internal labels
                    if (this_def['area'] == 'code') :    # only internal labels
                        address_found = False
                        for search in disassembly :
                            if (search['pos'] == data['target_address']) :
                                add_me = 0
                                address_found = True
                                break
                        if (address_found == False) :
                            for search in disassembly :
                                if (search['pos'] == data['target_address']-1) :
                                    add_me = 1
                                    address_found = True
                                    break
                        if (address_found == False) :
                            for search in disassembly :
                                if (search['pos'] == data['target_address']-2) :
                                    add_me = 2
                                    address_found = True
                                    break
                        if (address_found == False) :
                            #this should never happen
                            print('Address $%04x for label \"%s\" cannot be found.' %( data['target_address'],label_name) )
                    
                    #everything alright, apppend it to the list
                    tmp = {
                        'name':label_name,
                        'address':data['target_address'],
                        'type':this_def['area_type'],
                        'add': add_me,
                        'comment': this_def['comment']
                    }
                    my_label.append(tmp)   #append this label to the general list
                    #this_def['number'] +=1 #increase number of label
                    label_counter[this_def['area_type']] +=1 #increase number of label
                    break

    return my_label





def _do_it(
        args
    ) :

# sanity checks        
    try:
        my_address = int (args.startaddress, 16)	#convert from hex string
    except ValueError as err:
        print("error: address {0}".format(err))
        sys.exit(1)
        
    try:
        my_offset = int (args.offset, 16)	#convert from hex string
    except ValueError as err:
        print("error: offset {0}".format(err))
        sys.exit(1)
        
    try:
        my_limit = int (args.limit, 16)	#convert from hex string
    except ValueError as err:
        print("error: limit {0}".format(err))
        sys.exit(1)
        


    
    global string_comment, string_label, string_byte
    if (args.asmtype == 'acme') :
        string_comment = ASM_STRING['acme']['comment']
        string_label = ASM_STRING['acme']['label']
        string_byte = ASM_STRING['acme']['byte']
    if (args.asmtype == 'kickass') :
        string_comment = ASM_STRING['kickass']['comment']
        string_byte = ASM_STRING['kickass']['byte']



    buffer = _read_file( args.input_file, my_offset, my_limit )

    disassembly = _create_disassembly( buffer, my_address )
    
    labels = _create_labels ( disassembly, args.label_file, my_address, my_limit )
        
    _write_header (
        PROGNAME,
        VERSION,
        DATUM,
        args.input_file,
        my_address,
        my_offset,
        my_limit
    )    

    


    if (args.memorydump == True) : _write_memory_dump ( buffer, my_address )


    _write_disassembly(
        disassembly, 
        my_address,
        args.asmtype,
        args.cycles,
        args.illegals,
        labels
    )

    if (args.labellist == True) : _write_labels (labels)

    _save_file( args.output_file )

    print ("done.")
    
    
    
    return None



def _main_procedure() :
    print("%s v%s [%s] *** by fieserWolF"% (PROGNAME, VERSION, DATUM))

    #https://docs.python.org/3/library/argparse.html
    parser = argparse.ArgumentParser(
        description='This program disassembles 6502 code.',
        epilog='Example: ./dissector.py test.prg test.a 2000 -lf c64labels.json -o 2 -l 100 -t acme --dump --labels --illegals --cycles'
    )
    parser.add_argument('input_file', help='binary input file')
    parser.add_argument('output_file', help='sourcecode output file')
    parser.add_argument('startaddress', help='startaddress in hex')
    parser.add_argument('-lf', '--label-file', dest='label_file', help='labels json-file, default=\"c64labels.json\"', default='c64labels.json')
    parser.add_argument('-o', '--offset', dest='offset', help='offset in hex', default='0')
    parser.add_argument('-l', '--limit', dest='limit', help='limit in hex', default='0')
    parser.add_argument('-t', '--asmtype', dest='asmtype', help='assembler-type', choices=['acme','kickass'], default='acme', required=False)
    parser.add_argument('-d', '--dump', dest='memorydump', help='show memory-dump',  action='store_true')
    parser.add_argument('-i', '--illegals', dest='illegals', help='use illegal opcodes', action='store_true')
    parser.add_argument('-ll', '--labels', dest='labellist', help='show label-list', action='store_true')
    parser.add_argument('-cc', '--cycles', dest='cycles', help='show cycles', action='store_true')
    args = parser.parse_args()

    _do_it(args)


if __name__ == '__main__':
    _main_procedure()
