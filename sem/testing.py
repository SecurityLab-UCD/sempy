#!/usr/bin/env python3
import os
import subprocess
import re
from subprocess import CompletedProcess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from tempfile import TemporaryDirectory

from emulation import EmulationContext, Randomizer


class ProgramProvider(ABC):
    @abstractmethod
    def get(self, experiment: "Experiment") -> tuple[list[str], dict[str, bytes]]:
        """Generate program machine code for each optimization level (.text
        section only)."""
        # FIXME: refine interface; function name, function addresses, .text bytes, ?
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

    def __post_init__(self):
        self.randomizer.seed = self.initial_seed

    def run(self):
        programs = self.program_provider.get()
        # FIXME: implement
        # TODO: incorporate AFL++; instrument opt & llc?
        pass


class CSmithProvider(ProgramProvider):
    """Generate programs with CSmith and compile with clang."""

    def get(self, experiment: Experiment) -> tuple[list[str], dict[str, bytes]]:
        """Generate programs for all specified optimization levels."""
        with TemporaryDirectory("/dev/shm") as tmpdir:
            csmith_proc: CompletedProcess = subprocess.run(
                [
                    "csmith",
                    "-s",
                    str(experiment.randomizer.get()),
                    "--max-funcs",
                    "5",
                    "--no-global-variables",
                    "--no-builtins",
                    "--concise",
                    "--no-structs",
                    "--no-unions",
                ],
                capture_output=True,
            )
            source: str = csmith_proc.stdout.decode("utf-8")
            # Remove `static` to make sure that function symbols are exported
            source = source.replace("static ", "")
            source_path = os.path.join(tmpdir, "source.c")
            with open(source_path, "w") as source_file:
                source_file.write(source)

            # FIXME: add these options to clang
            # -fno-builtin-memset
            # -fno-builtin-memcpy
            # -fno-builtin-strlen
            # -fno-builtin-strcat
            # -fno-builtin-strcpy
            # -fno-builtin-strcmp
            # -fno-builtin-strncmp
            # -fno-builtin-atoi
            # -fno-builtin-atol
            # -fno-builtin-atof
            # TODO: get function list -> choose fn with arg -> extract ret ty & arg tys -> extract address

            program_images: dict[str, bytes] = []
            for opt_level in experiment.opt_levels:
                elf_path = os.path.join(tmpdir, f"{opt_level}.elf")
                bin_path = os.path.join(tmpdir, f"{opt_level}.bin")

                # FIXME: remove libc calls while keeping generated functions' symbols exported
                subprocess.run(["clang", source_path, f"-O{opt_level}", "-o", bin_path])
                subprocess.run(["objcopy", "-O", "binary", elf_path, bin_path])
                with open(bin_path, "rb") as program:
                    program_images[f"-O{opt_level}"] = program.read()
            return None, program_images

    @property
    def name(self) -> str:
        return "CSmith"


class IRFuzzerProvider(ProgramProvider):
    MUTATION_ITERS = 50

    # TODO: implement
    def get(self, experiment: Experiment) -> tuple[list[str], dict[str, bytes]]:
        # TODO: architecture handling?
        with TemporaryDirectory("/dev/shm") as tmpdir:
            ir_bc_path = os.path.join(tmpdir, "out.bc")
            open(ir_bc_path, 'wb').close()  # echo -n > $ir_bc_path
            # TODO: Where is the return value stored in for very large vectors?
            #       Is there a max return size?
            # TODO: MutatorDriver spit out function arg types, maybe even choose
            #       (top-of-call-graph) function for sempy? Seems like it's always f though.
            # NOTE: IRFuzzer & llvm-project sempy branch
            #       - no global variable src / sink
            #       - all functions in source must have definitions (so that they can be emulated)
            #       - createFunctionDefinition: ArgNum in interval of [1, 8]
            for _ in range(self.MUTATION_ITERS):
                subprocess.run(
                    ["MutatorDriver", ir_bc_path, str(experiment.randomizer.get())]
                )
            subprocess.run(["llvm-dis", "-opaque-pointers", ir_bc_path])
            ir_ll_path = os.path.join(tmpdir, "out.ll")
            name, tys = self._choose_fn(experiment, ir_ll_path)

            for opt_level in experiment.opt_levels:
                subprocess.run(
                    [
                        "opt",
                        "--opaque-pointers",
                        f"--O{opt_level}",
                        ir_ll_path,
                        "-o",
                        ir_bc_path,
                    ]
                )
            # NOTE: alloca ref: https://llvm.org/docs/LangRef.html#alloca-instruction
            # TODO: make sure that addressspace is specified, so that alloca still allocates on *stack*
            # TODO: llc; try to disable memcpy and other builtins if used
            # TODO: read program images
            return None, None

    def _choose_fn(
        self, experiment: Experiment, ir_ll_path: str
    ) -> tuple[str, list[str]]:
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
            return 'f', self._parse_arg_tys(arg_list)

    def _parse_arg_tys(self, arg_list: str) -> list[str]:
        # FIXME: implement
        args: list[str] = [ty.strip() for ty in arg_list.split(sep=",")]
        match_vec_ty = r"^<(?P<veclen>\d+) x (?P<elemty>.*)>"
        arg_tys: list[str] = []
        for arg in args:
            m = re.match(match_vec_ty, arg)
            # FIXME: implement
            if not m:
                pass

            arg_tys.extend(self._parse_arg_ty(arg))
        return arg_tys
    
    def _parse_arg_ty(self, arg_ty: str) -> list[str]:
        # NOTE: returns a list, e.g. <32 x i32> becomes []
        # TODO: investigate what <32 x i32> gets compiled into
        pass

    @property
    def name(self) -> str:
        return "IRFuzzer"
