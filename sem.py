#!/usr/bin/env python3
import logging
import secrets
from argparse import ArgumentParser, Namespace
from functools import partial
from binascii import hexlify

from tqdm import tqdm
from unicorn import Uc, UcError, UC_SECOND_SCALE
from prettytable import PrettyTable

from sem.emulation import (
    EmulationContext,
    Randomizer,
    DefaultRandomizer,
    Variable,
    VarAttr,
)

log = logging.Logger(__name__)


def parse_args() -> Namespace:
    """Parse command-line arguments and error-check."""
    parser = ArgumentParser(description="Compare assembly semantics through emulation")

    parser.add_argument("-a", "--arch", default="x86")
    parser.add_argument("-m", "--mode", default="64")
    parser.add_argument("-c", "--count", type=int, default=1000)
    parser.add_argument("-s", "--seed", type=int, default=secrets.randbits(64))
    parser.add_argument(
        "-t",
        "--types",
        type=partial(str.split, sep=","),
        default=[],
        help="Function argument types (format: [i|f|v|p][bitsize]) (e.g. i64)",
    )
    parser.add_argument("samples", nargs="+", help="Sample files to compare")
    args = parser.parse_args()

    if len(args.samples) == 1:
        parser.error("Expected two or more sample files")

    for arg_type in args.types:
        if len(arg_type) < 2:
            parser.error(f"Argument type too short: {arg_type}")
        if arg_type[0] not in ["i", "f", "v", "p"]:
            parser.error(f"Invalid argument type: {arg_type[0]}")
        if not str.isnumeric(arg_type[1:]):
            parser.error(f"Invalid argument bit size: {arg_type[1:]}")

    return args


def run_sample(
    emulator: Uc,
    emu_begin: int,
    emu_end: int,
    context: EmulationContext,
    randomizer: Randomizer,
    timeout: int,
) -> dict[str, bytes]:
    """Emulate a single sample."""
    try:
        randomizer.update(emulator, context)
        emulator.emu_start(emu_begin, emu_end, timeout)
    except UcError as e:
        pc = emulator.reg_read(context.pc_const)
        pc -= context.program_base
        log.critical(f"Exception encountered at PC=0x{pc:x}:")
        log.critical(f"Failed to emulate: {e}", exc_info=True)
        exit(1)


def diff_variables(
    emulators: list[Uc], context: EmulationContext
) -> dict[Variable, list[bytes]]:
    """Return the variables that differ across dumps."""
    res_vars: list[Variable] = context.result_variables
    diff: dict[Variable, list[bytes]] = {}
    for var in res_vars:
        values = [var.get(emu) for emu in emulators]
        if all(values[0] == value for value in values[1:]):
            continue
        diff[var] = values
    return diff


def make_diff_table(diff: dict[Variable, list[bytes]], sample_names: list[str]):
    table = PrettyTable(["Variable", *sample_names])
    for var, values in diff.items():
        if var.attr & VarAttr.REGISTER:
            size = var.size * 2
            values = [
                "0x" + hexlify(val).decode("ascii").rjust(size, "0") for val in values
            ]
        else:
            # Limit display size to 16 bytes of data (32 hex chars).
            values = [hexlify(val).decode("ascii") for val in values]
            values = [f"{val[:32]}..." if len(val) > 32 else val for val in values]
        table.add_row([var.name, *values])
    return table


def main():
    args = parse_args()

    context = EmulationContext.get(args.arch, args.mode)
    context.set_arg_types(args.types)
    randomizer = DefaultRandomizer(args.seed)
    samples = [open(sample_file, "rb").read() for sample_file in args.samples]
    samples_emu_info = [context.make_emulator(sample) for sample in samples]

    for _ in tqdm(range(args.count)):
        timeout = 10 * UC_SECOND_SCALE
        for emu_info in samples_emu_info:
            run_sample(*emu_info, context, randomizer, timeout)
        diff = diff_variables([emu_info[0] for emu_info in samples_emu_info], context)

        if len(diff) == 0:
            # Every register has the same value across samples
            randomizer.next_round()
            continue

        print(f"Found difference with seed={randomizer.last_seed}\n")

        print(make_diff_table(diff, args.samples))
        exit(1)
    else:
        print("No difference found.")


if __name__ == "__main__":
    main()
