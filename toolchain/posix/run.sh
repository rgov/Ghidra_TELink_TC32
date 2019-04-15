#!/bin/sh
wine "$(dirname "$0")"/../win32/tc32-elf-"$(basename "$0")".exe
