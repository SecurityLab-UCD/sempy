#!/usr/bin/env python3
import logging
import sem
from sem.common import EmulationContext, RegisterRandomizer

from unicorn import *
from argparse import ArgumentParser, Namespace
import secrets
from tqdm import tqdm

log = logging.Logger(__name__)


def parse_args() -> Namespace:
    parser = ArgumentParser(
        description='Compare assembly semantics through emulation')
    
    parser.add_argument('-a', '--arch', default='x86')
    parser.add_argument('-m', '--mode', default='64')
    parser.add_argument('-c', '--count', default=1000)
    parser.add_argument('-s', '--seed', default=secrets.randbits(64))
    parser.add_argument('sample_a', help='First sample file to test')
    parser.add_argument('sample_b', help='Second sample file to test')

    return parser.parse_args()


def main():
    args = parse_args()

    sample_a = open(args.sample_a, 'rb').read()
    sample_b = open(args.sample_b, 'rb').read()
    count = int(args.count)
    context = EmulationContext.get(args.arch, args.mode)
    randomizer = RegisterRandomizer()
    randomizer.seed = int(args.seed)

    a_emu, a_beg, a_end = context.make_emulator(sample_a)
    b_emu, b_beg, b_end = context.make_emulator(sample_b)

    for _ in tqdm(range(count)):
        try:
            TIMEOUT = 10 * UC_SECOND_SCALE

            cur_emu = a_emu
            randomizer.update(a_emu, context)
            a_emu.emu_start(a_beg, a_end, TIMEOUT)
            a_regs = context.dump_registers(a_emu)

            cur_emu = b_emu
            randomizer.seed = randomizer.last_seed
            randomizer.update(b_emu, context)
            b_emu.emu_start(b_beg, b_end, TIMEOUT)
            b_regs = context.dump_registers(b_emu)

            if a_regs == b_regs:
                continue

            print(f"Found difference with seed={randomizer.last_seed}")

            registers = context.register_consts()
            for regname in registers.keys():
                if regname not in a_regs and regname not in b_regs:
                    continue
                if a_regs[regname] != b_regs[regname]:
                    print(f'{regname}:\t{a_regs[regname]:08x}\t{b_regs[regname]:08x}')
            break
        except UcError as e:
            cur_pc = cur_emu.reg_read(context.pc_const()) - EmulationContext.PROGRAM_BASE
            log.critical(f"Exception encountered at PC=0x{cur_pc:x}:")
            log.critical(f"Failed to emulate: {e}", exc_info=True)
            exit(1)

    else:
        print('No difference found.')


if __name__ == '__main__':
    main()