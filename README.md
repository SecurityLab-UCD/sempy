# SemPy

A tool intended for preventing compiler regressions by comparing different
machine code compiled from the same assembly code.

Name subject to change.

## Requirements

```shell
pip install unicorn pwntools tqdm prettytable
```

## Example

```shell
# assemble into ELF format
as foo.a.s -o foo.a.elf
as foo.b.s -o foo.b.elf
# copy executable code out of ELF format
objcopy -O binary foo.a.elf foo.a.bin
objcopy -O binary foo.b.elf foo.b.bin
# emulate and compare
./sem.py --arch x86 --mode 64 --count 10000 --seed 12345 foo.{a,b}.bin
```

If you encounter an "Invalid instruction" error, chances are Unicorn Engine /
QEMU does not support the associated CPU extension yet.