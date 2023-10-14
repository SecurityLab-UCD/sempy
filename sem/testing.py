#!/usr/bin/env python3
import contextlib
import logging
import os
import re
import subprocess
from abc import ABC, abstractmethod
from binascii import hexlify
from dataclasses import dataclass
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
import tempfile

from prettytable import PrettyTable
from tqdm import tqdm
from unicorn import Uc, UcError

# XXX: DEBUG
from unicorn.unicorn_const import *

from .emulation import EmulationContext, Randomizer, VarAttr, Variable

log = logging.Logger(__name__)


@dataclass
class Program:
    name: str  # name of program (e.g. optimization level)
    image: bytes  # program image (.text section only)
    fn_arg_types: list[str]  # function argument types
    fn_start_offset: int  # address offset of the target function


class ProgramProvider(ABC):
    @abstractmethod
    def get(self, experiment: "Experiment") -> list[Program]:
        """Generate program machine code for each optimization level (.text
        section only)."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the program provider."""
        pass


@dataclass
class Experiment:
    """Class for testing compiler optimization passes."""

    name: str
    initial_seed: int
    program_provider: ProgramProvider
    opt_levels: set[str]
    repeat_count: int
    context: EmulationContext
    randomizer: Randomizer
    timeout: int

    def __post_init__(self):
        self.randomizer.seed = self.initial_seed
        # XXX: debug
        print(f"Initial seed: {self.initial_seed}")
        self._programs: list[Program] = []
        self._emulators: list[Uc] = []
        self._diff: dict[Variable, list[bytes]] = {}

    def run(self) -> bool:
        """Returns if there any varaible difference is found."""
        self.randomizer.next_round()
        self._programs = self.program_provider.get(self)
        assert len(self._programs) >= 2
        self.context.set_arg_types(self._programs[0].fn_arg_types)
        # XXX: debug
        print(len(self._programs[0].image))
        # FIXME: make use of fn start offset; don't assume it's 0 here
        emu_infos = [
            self.context.make_emulator(program.image) for program in self._programs
        ]
        self._emulators = [info[0] for info in emu_infos]
        # XXX: debug
        # for emulator, emu_begin, emu_end in emu_infos:
        #     def debug(emulator: Uc, address, size, user_data):
        #         print(f"RIP={address:x}")
        #         print(f"RSP={emulator.reg_read(self.context.register_consts['rsp']):x}")
        #         print(f"RBP={emulator.reg_read(self.context.register_consts['rbp']):x}")
        #         print('-'*15)
        #     emulator.hook_add(UC_HOOK_CODE, debug, None, 1, 0)

        for _ in tqdm(range(self.repeat_count)):
            for idx, emu_info in enumerate(emu_infos):
                emulator, emu_begin, emu_end = emu_info
                try:
                    self.randomizer.update(emulator, self.context)
                    emulator.emu_start(emu_begin, emu_end, self.timeout)
                    # FIXME: if timeout reached, ignore
                except UcError as e:
                    pc = emulator.reg_read(self.context.pc_const)
                    pc -= self.context.program_base
                    # NOTE: To debug: objdump -b binary -m i386:x86-64 -D 0_out.bin -M intel
                    # XXX: debug
                    print(
                        f"RAX={emulator.reg_read(self.context.register_consts['rax']):x}"
                    )
                    print(
                        f"RCX={emulator.reg_read(self.context.register_consts['rcx']):x}"
                    )
                    print(
                        f"RSP={emulator.reg_read(self.context.register_consts['rsp']):x}"
                    )
                    print(
                        f"RBP={emulator.reg_read(self.context.register_consts['rbp']):x}"
                    )

                    log.critical(f"Exception encountered at PC=0x{pc:x}:")
                    log.critical(
                        f"Failed to emulate {self._programs[idx].name}: {e}",
                        exc_info=True,
                    )
                    exit(1)
            self._diff_vars()

            # XXX: debug
            print(f"Initial seed = {self.initial_seed}")

            if len(self._diff):
                return True
        return False

    def _diff_vars(self) -> dict[Variable, list[bytes]]:
        """Updates self._diff with the variables that differ."""
        res_vars: list[Variable] = self.context.result_variables
        self._diff = {}
        for var in res_vars:
            values = [var.get(emu) for emu in self._emulators]
            if all(values[0] == value for value in values[1:]):
                continue
            self._diff[var] = values

    def make_diff_table(self):
        table = PrettyTable(["Variable", *[p.name for p in self._programs]])
        for var, values in self._diff.items():
            if var.attr & VarAttr.REGISTER:
                size = var.size * 2
                values = [
                    "0x" + hexlify(val).decode("ascii").rjust(size, "0")
                    for val in values
                ]
            else:
                # Limit display size to 16 bytes of data (32 hex chars).
                values = [hexlify(val).decode("ascii") for val in values]
                values = [f"{val[:32]}..." if len(val) > 32 else val for val in values]
            table.add_row([var.name, *values])
        return table


class CSmithProvider(ProgramProvider):
    """Generate programs with CSmith and compile with clang."""

    def get(self, experiment: Experiment) -> list[Program]:
        """Generate programs for all specified optimization levels."""
        with TemporaryDirectory(prefix="/dev/shm/") as tmpdir:
            # Remove `static` to make sure that function symbols are exported

            csmith_proc: CompletedProcess = subprocess.run(
                [
                    "csmith",
                    "-s",
                    str(experiment.randomizer.get()),
                    "--max-funcs",
                    "5",
                    "--no-global-variables",
                    "--nomain" "--no-checksum" "--no-builtins",
                    "--concise",
                    "--no-structs",
                    "--no-unions",
                ],
                capture_output=True,
            )
            source = csmith_proc.stdout.decode("utf-8")
            source = source.replace("static ", "")
            source_path = os.path.join(tmpdir, "source.c")
            with open(source_path, "w") as source_file:
                source_file.write(source)

            # FIXME: Get function list -> choose fn with arg -> extract ret ty & arg tys -> extract address
            #        To get things working, consider just regex-searching IR instead of parsing C

            programs: list[Program] = []

            for opt_level in experiment.opt_levels:
                ll_path = os.path.join(tmpdir, f"{opt_level}.ll")
                elf_path = os.path.join(tmpdir, f"{opt_level}.o")
                bin_path = os.path.join(tmpdir, f"{opt_level}.bin")

                subprocess.run(
                    [
                        "clang",
                        "-S",
                        "-emit-llvm",
                        f"-O{opt_level}",
                        "-nostdlib",
                        "-ffreestanding",
                        "-fno-builtin",
                        source_path,
                        "-o",
                        ll_path,
                    ]
                )
                subprocess.run(
                    [
                        "opt",
                        "-S",
                        f"-O{opt_level}",
                        "-disable-simplify-libcalls",
                        ll_path,
                        "-o",
                        ll_path,
                    ]
                )
                subprocess.run(
                    ["clang", f"-O{opt_level}", "-c", ll_path, "-o", elf_path]
                )
                subprocess.run(
                    ["objcopy", "-O", "binary", "-j", ".text", elf_path, bin_path]
                )
            ll_path = os.path.join(tmpdir, f"{experiment.opt_levels[0]}.ll")
            with open(ll_path, 'r') as ll_file:
                ll = ll_file.read()

            for opt_level in experiment.opt_levels:
                bin_path = os.path.join(tmpdir, f"{opt_level}.bin")
                with open(bin_path, "rb") as program:
                    # FIXME: find start address of target function
                    programs.append(
                        Program(f"-O{opt_level}", program.read(), None, None)
                    )
            return programs

    def _choose_fn(self, experiment: Experiment, c_source: str) -> list[str]:
        match_signature = r"^define .*? @f\((?P<arg_list>.*)\) .*{"
        for line in c_source.split("\n"):
            m = re.fullmatch(match_signature, line)
            if not m:
                continue
            arg_list = m.group("arg_list")
            if not arg_list:
                raise RuntimeError("f has an empty parameter list!")
            return self._parse_arg_tys(arg_list)

    @property
    def name(self) -> str:
        return "csmith"


class IRFuzzerProvider(ProgramProvider):
    MUTATION_ITERS = 10

    def get(self, experiment: Experiment) -> tuple[list[str], dict[str, bytes]]:
        # TODO: architecture handling?
        # XXX: debug
        #      original: TemporaryDirectory(prefix="/dev/shm/")
        with contextlib.nullcontext(tempfile.mkdtemp()) as tmpdir:
            # with TemporaryDirectory(prefix="/dev/shm/") as tmpdir:
            # XXX: debug
            print(tmpdir)
            ir_bc_path = os.path.join(tmpdir, "out.bc")
            open(ir_bc_path, "w").close()
            # NOTE: IRFuzzer & llvm-project sempy branch
            #       - no global variable src / sink
            #       - all functions in source must have definitions (so that they can be emulated)
            #       - createFunctionDefinition: ArgNum in interval of [1, 8]
            # TODO: non-zero subprocess exit code handling
            for _ in range(self.MUTATION_ITERS):
                subprocess.run(
                    ["MutatorDriver", ir_bc_path, str(experiment.randomizer.get())],
                    cwd=tmpdir,
                    stderr=subprocess.DEVNULL,
                )
            ir_ll_path = os.path.join(tmpdir, "out.ll")
            subprocess.run(
                ["llvm-dis", "-opaque-pointers", ir_bc_path, "-o", ir_ll_path]
            )
            # always just choose f
            tys = self._choose_fn(experiment, ir_ll_path)

            programs: list[Program] = []
            for opt_level in experiment.opt_levels:
                ir_opt_ll_path = os.path.join(tmpdir, f"{opt_level}_out.ll")
                # FIXME: add a call to f so that opt doesn't consider f unreachable
                subprocess.run(
                    [
                        "opt",
                        "--opaque-pointers",
                        f"--O{opt_level}",
                        ir_ll_path,
                        "-o",
                        ir_opt_ll_path,
                        "-S",
                    ]
                )

                arch = experiment.context.arch
                asm_path = os.path.join(tmpdir, f"{opt_level}_out.s")
                llc_args = [
                    "llc",
                    f"-O{opt_level}",
                    "--opaque-pointers",
                    f"-mtriple={arch if arch != 'x86' else 'x86_64'}--",
                    ir_opt_ll_path,
                    "-o",
                    asm_path,
                ]
                if arch == "x86":
                    llc_args.append("-mattr=+sse,+sse2")
                subprocess.run(llc_args)

                elf_path = os.path.join(tmpdir, f"{opt_level}_out.elf")
                subprocess.run(["as", asm_path, "-o", elf_path])

                image_path = os.path.join(tmpdir, f"{opt_level}_out.bin")
                subprocess.run(
                    ["objcopy", "-O", "binary", "-j", ".text", elf_path, image_path]
                )

                with open(image_path, "rb") as image_file:
                    image = image_file.read()
                programs.append(Program(f"-O{opt_level}", image, tys, 0))
            # TODO: make sure that addressspace is specified, so that alloca still allocates on *stack*
            #       alloca ref: https://llvm.org/docs/LangRef.html#alloca-instruction
            # TODO: llc: check if memcpy and other builtins are used
            return programs

    def _choose_fn(self, experiment: Experiment, ir_ll_path: str) -> list[str]:
        match_signature = r"^define .*? @f\((?P<arg_list>.*)\) .*{"
        with open(ir_ll_path, "r") as ir_ll_file:
            ir_ll_source_lines = [line.rstrip() for line in ir_ll_file.readlines()]
        for line in ir_ll_source_lines:
            m = re.fullmatch(match_signature, line)
            if not m:
                continue
            arg_list = m.group("arg_list")
            if not arg_list:
                raise RuntimeError("f has an empty parameter list!")
            return self._parse_arg_tys(arg_list)

    def _parse_arg_tys(self, arg_list: str) -> list[str]:
        args: list[str] = [ty.strip() for ty in arg_list.split(sep=",")]
        arg_tys: list[str] = []
        for arg in args:
            match_vec_ty = r"^<(?P<veclen>\d+) x (?P<elemty>.*)>"
            m = re.match(match_vec_ty, arg)
            if m:
                ty = m.group("elemty")
                elemsize = 0
                if ty == "double":
                    elemsize = 64
                elif ty == "float":
                    elemsize = 32
                elif ty == "half":
                    elemsize = 16
                else:
                    elemsize = int(ty[1:])
                vecsize = int(m.group("veclen")) * elemsize
                arg_tys.append(f"v{vecsize}")
                continue

            match_scalar_ty = r"^([ifu]\d+|float|half|double|ptr)"
            m = re.match(match_scalar_ty, arg)
            if not m:
                raise RuntimeError(f"Cannot parse type: {arg}")

            if m.group(0) == "double":
                arg_tys.append("f64")
            elif m.group(0) == "float":
                arg_tys.append("f32")
            elif m.group(0) == "half":
                arg_tys.append("f16")
            elif m.group(0) == "ptr":
                arg_tys.append("p512")
            else:
                arg_tys.append(m.group(0))

        return arg_tys

    @property
    def name(self) -> str:
        return "irfuzzer"


class FileProvider(ProgramProvider):
    def __init__(self) -> None:
        super().__init__()
        self._filenames: list[str] = []
        self._images: list[bytes] = []
        self._argtys: list[str] = []

    def set_files(self, filenames: list[str], argtys: list[str]):
        self._filenames = filenames
        self._images: list[bytes] = []
        for filename in self._filenames:
            with open(filename, "rb") as file:
                self._images.append(file.read())
        self._argtys = argtys

    def get(self, experiment: Experiment) -> list[Program]:
        return [
            Program(filename, image, self._argtys, 0)
            for filename, image in zip(self._filenames, self._images)
        ]

    @property
    def name(self) -> str:
        return "file"
