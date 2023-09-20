#!/usr/bin/env python3
import logging
import secrets
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
from sem.testing import Experiment, ProgramProvider

log = logging.Logger(__name__)


def parse_args() -> Namespace:
    """Parse command-line arguments and error-check."""
    parser = ArgumentParser(description="Compare assembly semantics through emulation")

    parser.add_argument("-a", "--arch", default="x86")
    parser.add_argument("-m", "--mode", default="64")
    parser.add_argument("-c", "--count", type=int, default=10, help="Times to repeat for a single round")
    parser.add_argument("-e", "--experiments", type=int, default=1, help="Times to repeat experiment")
    parser.add_argument("-s", "--seed", type=int, default=secrets.randbits(64))
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
        choices=[Sub().name for Sub in ProgramProvider.__subclasses__()],
    )
    parser.add_argument(
        "-t",
        "--types",
        type=partial(str.split, sep=","),
        default=[],
        nargs="?",
        help="Function argument types (format: [iufvp]\\d+) (e.g. i64)",
    )
    parser.add_argument("files", default=[], nargs="*", help="Files to compare")
    args = parser.parse_args()

    if args.provider == "file":
        if len(args.files) < 2:
            parser.error("Expected two or more files to compare")
        for arg_type in args.types:
            if len(arg_type) < 2:
                parser.error(f"Argument type too short: {arg_type}")
            if arg_type[0] not in ["i", "f", "v", "p"]:
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

    return args


def main():
    args = parse_args()

    context = EmulationContext.get(args.arch, args.mode)
    provider = next(
        Sub() for Sub in ProgramProvider.__subclasses__() if Sub().name == args.provider 
    )
    if provider.name == "file":
        provider.set_files(args.files, args.types)

    expr = Experiment(
        f"{provider.name} -O{args.opt_levels}",
        args.seed,
        provider,
        [*args.opt_levels],
        args.count,
        context,
        DefaultRandomizer(),
        5 * UC_SECOND_SCALE,
    )

    for _ in range(args.experiments):
        if expr.run():
            print("Found difference")
            print(f"Seed = {expr.randomizer.last_seed}")
            print(expr.make_diff_table())


if __name__ == "__main__":
    main()
