#!/usr/bin/env python3
import logging
import secrets
from argparse import ArgumentParser, Namespace, ArgumentError
from functools import reduce

from tqdm import tqdm
from unicorn import Uc, UcError, UC_SECOND_SCALE
from prettytable import PrettyTable

from sem import EmulationContext, Randomizer, RegisterRandomizer

log = logging.Logger(__name__)


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description="Compare assembly semantics through emulation")
    
    parser.add_argument('-a', '--arch', default='x86')
    parser.add_argument('-m', '--mode', default='64')
    parser.add_argument('-c', '--count', type=int, default=1000)
    parser.add_argument('-s', '--seed', type=int, default=secrets.randbits(64))
    parser.add_argument('samples', nargs='+', help="Sample files to compare")
    args = parser.parse_args()

    if len(args.samples) == 1:
        parser.error("Expected two or more sample files")

    return args


def run_sample(emulator: Uc,
               emu_begin: int,
               emu_end: int,
               context: EmulationContext,
               randomizer: Randomizer,
               timeout: int) -> dict[str, int]:
    """Emulate a single sample and return register dump."""
    try:
        randomizer.update(emulator, context)
        emulator.emu_start(emu_begin, emu_end, timeout)
        return context.dump_registers(emulator)
    except UcError as e:
        pc = emulator.reg_read(context.pc_const)
        pc -= EmulationContext.PROGRAM_BASE
        log.critical(f"Exception encountered at PC=0x{pc:x}:")
        log.critical(f"Failed to emulate: {e}", exc_info=True)
        exit(1)


def diff_reg_dumps(dumps: list[dict[str, int]]) -> dict[str, list[int]]:
    """Return the register values that differ across dumps."""
    if len(dumps) < 2:
        return {}
    diff: dict[str, list[int]] = {}
    for register in dumps[0].keys():
        if all(dumps[0].get(register, None) == dump.get(register, None)
               for dump in dumps[1:]):
            continue
        diff[register] = [dump[register] for dump in dumps]
    return diff


def main():
    args = parse_args()

    context = EmulationContext.get(args.arch, args.mode)
    randomizer = RegisterRandomizer(args.seed)
    samples = [open(sample_file, 'rb').read() for sample_file in args.samples]
    samples_emu_info = [context.make_emulator(sample) for sample in samples]

    for _ in tqdm(range(args.count)):
        timeout = 10 * UC_SECOND_SCALE
        sample_reg_dumps = [run_sample(*emu_info, context, randomizer, timeout)
                            for emu_info in samples_emu_info]
        diff = diff_reg_dumps(sample_reg_dumps)

        if len(diff) == 0:
            # Every register has the same value across samples
            randomizer.next_round()
            continue

        print(f"Found difference with seed={randomizer.last_seed}\n")

        table = PrettyTable(['Register', *args.samples])
        for register, values in diff.items():
            # TODO: support n-tuple register_size return value
            size = context.register_size(register)[0] * 2
            values = ['0x' + f'{val:x}'.rjust(size, '0') for val in values]
            table.add_row([register, *values])
        print(table)
        exit(1)
    else:
        print("No difference found.")


if __name__ == '__main__':
    main()