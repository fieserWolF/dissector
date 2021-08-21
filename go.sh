#!/bin/bash -e
./dissector.py test.prg test.a 2000 -lf c64labels.json -o 1002 -l 0500 -t acme -i --labels --dump --cycles

exit 0



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
