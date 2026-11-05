# Telink TC32 Processor Specification for Ghidra

This repository contains a fairly complete processor specification for the Telink TC32 architecture, used by all of Telink's System-On-Chips. The work herein is based on Ryan Govostes' work and extended with various fix-ups and actual P-code implementation.

[Ghidra]: https://www.nsa.gov/resources/everyone/ghidra/

Right now decompilation is working well with several tested TC32 ELFs.


## Usage

Copy the  `Telink_TC32` repository to `Ghidra/Processors`. Restart Ghidra.
Afterwards, when importing a TC32 binary, when prompted for the binary's "Language", select the "Telink_TC32" processor.

For analysing Telink ELFs, I use the following process (using some plugins from my GhidraPlugins repo):
1. Import the binary, do not Auto-Analyse
2. Run the fix_funcnames.py plugin
3. Run the disas_symbols.py plugin
4. Run the Auto-Analysis, without call convention identification
5. Parse the register header file into the Data Type Manager (Grab the Telink SDK, redefine the REG_ADDR%X macros in register_82XX.h as integers instead of as pointers)
6. Export the register/defines values just imported from the Data Type Manager
7. Re-Import them as labels using the exptoimp.py plugin
8. Define a new memory region via the Memory Map. For the 826x SoCs, registers are at 0x00800000, length 0x8000.

At this point the decompilation should be fairly accurate and resolve references very nicely.


## Architecture Notes

The TC32 is fairly similar to 16-bit ARM9 Thumb instruction set.

ELF binaries for TC32 use the machine type identifier 58.


## Development Notes

As said, I used RGov's work as a basis and continued from there.
The Telink SDK contains the binutils readelf and objdump, Ryan reverse engineered the compiled objdump and found it mostly used the Thumb disassembler from ['arm-dis.c']. The opcode masks and values and the assembler format strings for each instruction were extracted. 

[arm-dis.c]: http://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob;f=opcodes/arm-dis.c;hb=HEAD

He then made the `generate_sleigh.py` script which uses the extracted opcode table to create sleigh instruction symbols and added some sensible defaults for register, RAM definitions and so on.

From here I made several improvements:
1. Fixed incorrect jump offsets
2. Defined register lists for push, pop, store, load commands ( for example tpush {r1, r2, lr} )
3. Added the 32-bit jump and link instruction
4. Added calling conventions and full P-Code implementation of the instruction set, to support the decompiler engine.

Most of the work was done by using the arm-dis.c file and the Ghidra Thumb processor specification, making adjustments when needed.
