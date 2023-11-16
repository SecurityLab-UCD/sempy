# SemPy

A tool for testing compiler optimization by compiling the same code under
various optimization levels and comparing emulation results.

Currently, only x86 is supported.

Name subject to change.

## Requirements

```shell
poetry install
```

Please ensure that the target LLVM binaries are in PATH.

In addition, download and `make` CSmith runtime files in home directory (i.e.
`~/csmith/runtime`).  In the future, the location of the runtime directory will
be changed into a command-line option that defaults to the system install
location of libcsmith0 package.

For [IRFuzzer](https://github.com/SecurityLab-UCD/IRFuzzer)-related program
providers such as `irfuzzer` and `mutate-csmith`, please ensure that the
MutatorDriver is compiled and present in PATH.

## Example

```shell
# -e 0: Use all cores to compare -O0 and -O3
./sem.py -p mutate-csmith -e 0 -o ./experiment -O03
```

To terminate, Ctrl+C and run `pkill -f sem.py`. Relevant program seeds can be
found in the specified output directory.