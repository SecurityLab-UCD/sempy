#!/usr/bin/env python3
import os
import subprocess
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
            with open(source_path, 'w') as source_file:
                source_file.write(source)

            # TODO: get function list -> choose fn with arg -> extract ret ty & arg tys -> extract address

            program_images: dict[str, bytes] = []
            for opt_level in experiment.opt_levels:
                elf_path = os.path.join(tmpdir, f"{opt_level}.elf")
                bin_path = os.path.join(tmpdir, f"{opt_level}.bin")

                # FIXME: remove libc calls while keeping generated functions' symbols exported
                subprocess.run(["clang", source_path, f"-O{opt_level}", "-o", bin_path])
                subprocess.run(
                    ["objcopy", "-O", "binary", elf_path, bin_path]
                )
                with open(bin_path, "rb") as program:
                    program_images[f"-O{opt_level}"] = program.read()
            return None, program_images

    @property
    def name(self) -> str:
        return "CSmith"


class IRFuzzerProvider(ProgramProvider):
    # TODO: implement
    pass
