#!/usr/bin/env python3
import logging
import multiprocessing
import os
import secrets
import time
from argparse import ArgumentParser, Namespace
from itertools import count
from functools import partial

from unicorn import UC_SECOND_SCALE

from sem.emulation import (
    DefaultRandomizer,
    EmulationContext,
)
from sem.fuzzing import Experiment, ProgramProvider, RunStatus

logging.root.setLevel(logging.INFO)
log = logging.Logger(__name__, logging.INFO)
logging.Logger("pwnlib.asm").propagate = False


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
        "-c",
        "--count",
        type=int,
        default=10,
        help="Fuzz a generated program/function COUNT times",
    )
    parser.add_argument(
        "-e",
        "--experiments",
        type=int,
        default=1,
        help="Number of parallel experiments (0 to use CPU count)",
    )
    parser.add_argument(
        "-M",
        "--max-programs",
        type=int,
        default=0,
        help="Max generated programs per experiment (default: unlimited)",
    )
    parser.add_argument(
        "-s", "--seed", type=int, default=secrets.randbits(64), help="Initial seed"
    )
    parser.add_argument(
        "-o", "--outdir", default="/dev/shm/sempy", help="Experiment output root"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=0, help="Experiment timeout (seconds)"
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
        default="mutate-csmith",
        choices=[Sub().name for Sub in all_subclasses(ProgramProvider)],
    )
    parser.add_argument(
        "-r",
        "--repro",
        type=int,
        default=None,
        help="Reproduce a program seed (--program-seed REPRO --once --debug)",
    )
    parser.add_argument(
        "--program-seed",
        type=int,
        default=None,
        help="Seed for replicating a specific program",
    )
    parser.add_argument("--once", action="store_true", help="Emulate once and quit")
    parser.add_argument("-d", "--debug", action="store_true", help="Show debug output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress output")
    # -p file only
    parser.add_argument(
        "-T",
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
        if args.repro is not None:
            args.program_seed = args.repro
            args.debug = True
            args.once = True
    args.outdir = os.path.join(args.outdir, "")

    return args


def fuzz(args: Namespace, seed: int):
    start_time = time.time()
    context = EmulationContext.get(args.arch, args.mode)
    provider = next(
        Sub() for Sub in all_subclasses(ProgramProvider) if Sub().name == args.provider
    )
    if provider.name == "file":
        provider.set_files(args.files, args.types)

    expr = Experiment(
        f"{provider.name} -O{args.opt_levels}",
        args.outdir,
        seed,
        provider,
        [*args.opt_levels],
        args.count,
        context,
        DefaultRandomizer(),
        int(0.5 * UC_SECOND_SCALE),
        args.debug,
    )

    for i in count(start=1):
        status, program_seed = expr.run(args.program_seed)
        if not args.quiet:
            match status:
                case RunStatus.RUN_DIFF:
                    print("Difference found")
                    if args.debug:
                        print(program_seed)
                        print(expr.make_diff_table())
                case RunStatus.RUN_OK:
                    print("No difference found")
                case RunStatus.RUN_EMU_EXC:
                    print("Emulation exception")
                case RunStatus.RUN_GEN_EXC:
                    print("Program generation exception")
                case RunStatus.RUN_TIMEOUT:
                    print("Emulation timeout reached")
        current_time = time.time()
        if args.once or i == args.max_programs:
            break
        # No need for precise timeouts, since each expr.run() finishes within a second
        if args.timeout != 0 and current_time - start_time > args.timeout:
            break


def main():
    args = parse_args()
    processes = []

    rand = DefaultRandomizer(args.seed)
    if args.experiments == 0:
        args.experiments = multiprocessing.cpu_count()
    elif args.experiments == 1:
        fuzz(args, rand.get())
        return

    for _ in range(args.experiments):
        process = multiprocessing.Process(target=fuzz, args=(args, rand.get()))
        time.sleep(0.5)  # suppress pwnlib term init error
        processes.append(process)
        process.start()

    for process in processes:
        process.join()


if __name__ == "__main__":
    main()
