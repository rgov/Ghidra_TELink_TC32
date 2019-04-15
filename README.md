# Telink TC32 Processor Specification for Ghidra

This repository contains a work-in-progress [Ghidra][] processor specification for the Telink TC32 microcontroller. The TC32 ISA is used by the Lenze 17HXX (e.g., ST17H26) family of BTLE SoCs.

[Ghidra]: https://www.nsa.gov/resources/everyone/ghidra/

Currently, the specification allows Ghidra to **roughly** disassemble TC32 machine code. No instruction semantics (i.e., p-code) is implemented, so decompilation is not yet possible.


## Usage

The processor specification in the directory `Telink_TC32` can be installed into `Ghidra/Processors`. Restart Ghidra after doing so.

Afterwards, when importing a TC32 binary, when prompted for the binary's "Language", select the "Telink_TC32" processor.


## Architecture Notes

The TC32 is essentially a clone of the 16-bit ARM9 Thumb instruction set.

ELF binaries for TC32 use the machine type identifier 58.


## Development Notes

The processor specification was bootstrapped by reverse engineering `tc32-elf-objdump.exe` (see below), which reuses most of the implementation of the Thumb disassembler from [`arm-dis.c`][arm-dis.c]. The opcode masks and values and the assembler format strings for each instruction were extracted.

[arm-dis.c]: http://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob;f=opcodes/arm-dis.c;hb=HEAD

The `generate_sleigh.py` script parses the assembler format strings and determines which bits of the encoded instruction need to be extracted for each operand. It then generates a skeletal SLEIGH file, which must be filled in by hand.

 
### Writing SLEIGH

Documentation on SLEIGH is included in the Ghidra distribution in `docs/languages/html/sleigh.html`.

The specification can be compiled using:

    $GHIDRA/support/sleigh \
    -i Telink_TC32/data/sleighArgs.txt \
    Telink_TC32/data/languages/Telink_TC32.slaspec \
    Telink_TC32/data/languages/Telink_TC32.sla


### "Forward-Engineering" Toolchain

Telink provides an Eclipse-based [IDE][] for Windows that comes with binaries of GCC and binutils that support the architecture. At the time of writing, Telink had not released source code in compliance with the GNU General Public License.

The binaries have been redistributed here and can be executed on macOS and Linux using [Wine][].

[IDE]: http://wiki.telink-semi.cn/dokuwiki/doku.php?id=menu:tools:ide_quick_start
[Wine]: https://www.winehq.org
