#!/usr/bin/env python3
import logging
import multiprocessing
import os
import secrets
import time
from argparse import ArgumentParser, Namespace
from binascii import hexlify
from functools import partial

from prettytable import PrettyTable
from tqdm import tqdm
from unicorn import UC_SECOND_SCALE, Uc, UcError

from sem.emulation import (
    DefaultRandomizer,
    EmulationContext,
    Randomizer,
    VarAttr,
    Variable,
)
from sem.testing import Experiment, ProgramProvider, RunStatus

log = logging.Logger(__name__)


def all_subclasses(cls):
    return set(cls.__subclasses__()).union(
        [s for c in cls.__subclasses__() for s in all_subclasses(c)]
    )


def parse_args() -> Namespace:
    """Parse command-line arguments and error-check."""
    parser = ArgumentParser(description="Compare assembly semantics through emulation")

    parser.add_argument("-a", "--arch", default="x86", help="Architecture (e.g. x86)")
    parser.add_argument("-m", "--mode", default="64", help="Emulation mode (e.g. 64)")
    parser.add_argument(
        "-c", "--count", type=int, default=10, help="Times to repeat for a single round"
    )
    parser.add_argument(
        "-e", "--experiments", type=int, default=1, help="Number of parallel experiments (0 to use CPU count)"
    )
    parser.add_argument(
        "-s", "--seed", type=int, default=secrets.randbits(64), help="Experiment seed"
    )
    parser.add_argument(
        "-o", "--outdir", default="/dev/shm/sempy", help="Experiment output root"
    )
    parser.add_argument(
        "-O",
        "--opt-levels",
        type=str,
        default="",
        required=False,
        help="Optimization levels to test (e.g. -O0123s)",
    )
    parser.add_argument(
        "-p",
        "--provider",
        required=True,
        choices=[Sub().name for Sub in all_subclasses(ProgramProvider)],
    )
    parser.add_argument(
        "--program-seed",
        type=int,
        nargs="?",
        help="Seed for replicating a specific program",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output")
    # -p file only
    parser.add_argument(
        "-t",
        "--types",
        type=partial(str.split, sep=","),
        default=[],
        nargs="?",
        help="Function argument types (format: /[iufvp]\\d+/) (e.g. i64)",
    )
    parser.add_argument("files", default=[], nargs="*", help="Files to compare")
    args = parser.parse_args()

    if args.provider == "file":
        if len(args.files) < 2:
            parser.error("Expected two or more files to compare")
        for arg_type in args.types:
            if len(arg_type) < 2:
                parser.error(f"Argument type too short: {arg_type}")
            if arg_type[0] not in ["i", "u", "f", "v", "p"]:
                parser.error(f"Invalid argument type: {arg_type[0]}")
            if not str.isnumeric(arg_type[1:]):
                parser.error(f"Invalid argument bit size: {arg_type[1:]}")
    else:
        if len(args.files) or len(args.types):
            parser.error(
                "Option --types and files are only supported for `file` provider"
            )
        if len(args.opt_levels) < 2:
            parser.error("Expected at least two optimization levels to compare")
    args.outdir = os.path.join(args.outdir, "")

    return args


def fuzz(args: Namespace):
    context = EmulationContext.get(args.arch, args.mode)
    provider = next(
        Sub() for Sub in all_subclasses(ProgramProvider) if Sub().name == args.provider
    )
    if provider.name == "file":
        provider.set_files(args.files, args.types)

    expr = Experiment(
        f"{provider.name} -O{args.opt_levels}",
        args.outdir,
        args.seed,
        provider,
        [*args.opt_levels],
        args.count,
        context,
        DefaultRandomizer(),
        int(0.5 * UC_SECOND_SCALE),
    )

    while True:
        status, program_seed = expr.run(args.program_seed)
        if status == RunStatus.RUN_DIFF:
            print(f"{program_seed}")
            if not args.quiet:
                print(expr.make_diff_table())


def main():
    args = parse_args()
    processes = []

    if args.experiments == 0:
        args.experiments = multiprocessing.cpu_count()

    for _ in range(args.experiments):
        process = multiprocessing.Process(target=fuzz, args=(args,))
        time.sleep(0.5)  # suppress pwnlib term init error
        processes.append(process)
        process.start()

    for process in processes:
        process.join()


if __name__ == "__main__":
    main()
