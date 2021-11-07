# Dissector

Dissector disassembles 6502 code.
As of now, this primarily is a commandline-tool, but there is an optional gui available.
It runs on 64 bit versions of Linux, MacOS, Windows and other systems supported by Python. 


# Why Dissector?

reason | description
---|---
open source | easy to modify and to improve, any useful contribution is highly welcome
portable | available on Linux, MacOS, Windows and any other system supported by Python3
illegals | full illegal opcode support
cycles | used cpu-cycles shown for each opcode
extensive info | extensive C64 memory map carefully gathered from best sources I could find online
assemblers | ACME and KickAssembler supported, easy to implement other assemblers


# Usage

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




Have a good look in /doc.



# C64 information sources

Graham`s 65xx resources
[http://www.oxyron.de/html/opcodes02.html](http://www.oxyron.de/html/opcodes02.html)
Copyright 2002-2012 Graham. Last change on 03.11.2012. 


book: Mapping the C64
[http://unusedino.de/ec64/technical/project64/mapping_c64.html](http://unusedino.de/ec64/technical/project64/mapping_c64.html)


Commodore 64 RAM Memory Map V1.2, published 1 Sep 1994
[ftp://arnold.c64.org/pub/docs/C64rom.lib](ftp://arnold.c64.org/pub/docs/C64rom.lib)
[ftp://arnold.c64.org/pub/docs/C64ram.doc](ftp://arnold.c64.org/pub/docs/C64ram.doc)



# Author

* fieserWolF/Abyss-Connection - *code* - [https://github.com/fieserWolF](https://github.com/fieserWolF) [https://csdb.dk/scener/?id=3623](https://csdb.dk/scener/?id=3623)
* Streetuff/TRSI - *code* - graphical user interface


# Getting Started

dissector comes in two flavors:

- standalone executable for 64-bit systems Linux, MacOS/Darwin and Windows (see [releases](https://github.com/fieserWolF/dissector/releases))
- Python3 script

## Run the standalone executable

Just download your bundle at [releases](https://github.com/fieserWolF/dissector/releases) and enjoy.
Keep in mind that only 64bit systems are supported as I could not find a 32bit system to generate the bundle.

### Note for Windows users

If some antivirus scanner puts dissector into quarantine because it suspects a trojan or virus, simply put it out there again.
It isn`t harmful, I used PyInstaller to bundle the standalone executable for you.
Unfortunately, the PyInstaller bootloader triggers a false alarm on some systems.
I even tried my best and re-compiled the PyInstaller bootloader so that this should not happen anymore. Keep your fingers crossed ;)

### Note for MacOS users

Your system might complain that the code is not signed by a certificated developer. Well, I am not, so I signed the program on my own. 
```
"dissector" can`t be opened because it is from an unidentified developer.
```
You need to right-click or Control-click the app and select “Open”.



## Run the Python3 script directly

Download _dissector.py_ and c64labels.json into the same folder on your computer.

    python3 dissector.py 



# graphical user interface

If you prefer a gui, start the script "gui.py":

    python3 gui.py 

This graphical interface was kindly provided by Streetuff/TRSI.
It uses PySimpleGUI library.


### Prerequisites

At least this is needed to run the script directly:

- python 3
- argparse
- PySimpleGUI (optional for the graphical user interface)

Normally, you would use pip like this:
```
pip3 install argparse pysimplegui
```

On my Debian GNU/Linux machine I use apt-get to install everything needed:
```
apt-get update
apt-get install python3 python3-argh
```
PySimpleGui is not included in Debian GNU/Linux yet. You have to install it with pip as described above.
# Changelog

## Future plans

- maybe: implement full GUI

Any help and support in any form is highly appreciated.

If you have a feature request, a bug report or if you want to offer help, please, contact me:

[http://csdb.dk/scener/?id=3623](http://csdb.dk/scener/?id=3623)
or
[wolf@abyss-connection.de](wolf@abyss-connection.de)


## Changes in 1.01

- bugfix: KERNEL labels appear in label-list now


## Changes in 1.00

- initial release

# License

_Dissector 6502 disassembler._

_Copyright (C) 2021 fieserWolF / Abyss-Connection_

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.
If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/).

See the [LICENSE](LICENSE) file for details.

For further questions, please contact me at
[http://csdb.dk/scener/?id=3623](http://csdb.dk/scener/?id=3623)
or
[wolf@abyss-connection.de](wolf@abyss-connection.de)

For Python3 and other used source licenses see file [LICENSE_OTHERS](LICENSE_OTHERS).


