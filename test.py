import contextlib
import importlib
import logging
import os
import pkgutil
from random import Random
import shutil
import subprocess
import tempfile
from typing import Iterable, Union
import unittest
from unicorn import Uc

print(os.getcwd())

from sem.emulation import (
    DefaultRandomizer,
    EmulationContext,
    Program,
    Randomizer,
    VarAttr,
)
from unicorn import UC_SECOND_SCALE
from sem.testing import Experiment, IRFuzzerProvider, MutateCSmithProvider, ProgramProvider, RunStatus

log = logging.Logger(__name__, logging.INFO)
out_dir = "/dev/shm/sempy/unittest/"


class TestProgramProvider(MutateCSmithProvider):
    def __init__(self, _test_file_path: str, context: EmulationContext) -> None:
        super().__init__()
        self._test_file_path = _test_file_path
        self._context = context

    @property
    def name(self) -> str:
        return "test-program"

    def get(self, placeholder = None) -> list[Program]:
        return [self._prepare_test()]

    def _prepare_test(self) -> Program:
        with contextlib.nullcontext(
            tempfile.mkdtemp(prefix=out_dir)
        ) as tmpdir:
            source_c_path = self._test_file_path
            context = self._context

            test_c_path = os.path.join(tmpdir, "out.c")
            test_ll_path = os.path.join(tmpdir, "out.ll")
            test_asm_path = os.path.join(tmpdir, "out.s")
            test_elf_path = os.path.join(tmpdir, "out.elf")
            image_path = os.path.join(tmpdir, "out.bin")
            test_bc_path = os.path.join(tmpdir, "out.bc")

            shutil.copy(source_c_path, test_c_path)

            CSMITH_RUNTIME = os.path.join(os.environ["HOME"], "csmith/runtime")

            subprocess.run(
                [
                    "clang",
                    "-S",
                    "-emit-llvm",
                    "-O0",
                    "-Xclang",
                    "-disable-O0-optnone",
                    f"-I{CSMITH_RUNTIME}",
                    "-nostdlib",
                    "-ffreestanding",
                    "-fno-builtin",
                    source_c_path,
                    "-o",
                    test_ll_path,
                ],
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(["llvm-as", test_ll_path])
            subprocess.run(["llvm-dis", test_bc_path])

            try:
                fn_name, ret_ty, arg_tys = self.choose_ir_fn(
                    None, test_ll_path)
            except:
                shutil.rmtree(tmpdir)
                raise

            mtriple = context.mtriple
            arch = context.arch

            llc_args = [
                "llc",
                f"-O1",
                f"-mtriple={mtriple}",
                test_ll_path,  # opt_ll_path,
                "-o",
                test_asm_path,
            ]
            if arch == "x86":
                llc_args += ["-mattr=+sse,+sse2", "--x86-asm-syntax=intel"]
            subprocess.run(llc_args)
            if arch == "x86":
                subprocess.run(["as", test_asm_path, "-o", test_elf_path])
            else:
                subprocess.run(["clang", "-c", f"{test_asm_path}", "-v",
                                f"--target={mtriple}",
                                "-fuse-ld=lld",
                                "-fintegrated-as",
                                "-o", test_elf_path])

            try:
                fn_offset = self.get_fn_offset(test_elf_path, fn_name)
            except:
                shutil.rmtree(tmpdir)
                raise
            subprocess.run(
                ["llvm-objcopy", "-O", "binary", "-j",
                    ".text", test_elf_path, image_path]
            )
            with open(image_path, "rb") as image_file:
                image = image_file.read()
            return Program(f"test_{context.arch}_{context.mode}", image, ret_ty, arg_tys, fn_offset, tmpdir)


class TestImplementations(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)

        self.contexts = [
            #EmulationContext.get("x86", "64"),
            EmulationContext.get("arm64", "arm"),
        ]

    def test_emulations(self, program_seed = None):
        test_experiments = []

        for context in self.contexts:
            testProgramProvider = TestProgramProvider("./testcases/out.c", context)
            testExperiment = Experiment(
                f"test_{context.arch}_{context.mode}",
                out_dir,
                program_seed,
                testProgramProvider,
                [],
                1,
                context,
                StubRandomizer(seed = 0, preset_vals = [10, 20, 30, 40]),
                int(0.5 * UC_SECOND_SCALE),
                True
            )
            test_experiments.append(testExperiment)

        for test in test_experiments:
            test.run(program_seed)

class StubRandomizer(DefaultRandomizer):
    """A simple randomizer that just update variables with random bytes. Handles
    VarAttr.PTR."""

    def __init__(self, seed: int = 0, preset_vals = []) -> None:
        super().__init__()
        self._random = Random()
        self.seed = seed
        self._last_seed = None
        self._index = 0
        self._preset_vals = preset_vals

    def update(self, emulator: Uc, context: EmulationContext):
        self._last_seed = self.seed
        for variable in context.variables:
            if variable.attr & VarAttr.PTR:
                # TODO: try to prevent overlapping
                data = self._random.randrange(*context.ptr_range, 0x10)
                data = data.to_bytes(variable.size, "big")
            else:
                data = self._preset_vals[self._index]
                data = data.to_bytes(variable.size, "big")
                self._index += 1
            print(f"{variable.name} {data}")
            variable.set(data, emulator)
        self.seed = self._last_seed

    def get(self) -> int:
        return self._random.randint(0, 2**64 - 1)

    def choice(self, obj: Iterable) -> any:
        return self._random.choice(obj)

    @property
    def last_seed(self) -> Union[int, None]:
        return self._last_seed

    @property
    def seed(self):
        return self._seed

    @seed.setter
    def seed(self, value):
        self._seed = value
        self._random.seed(self._seed)
        pass

    def next_round(self) -> int:
        self.seed = self.get()
        return self.seed



if __name__ == '__main__':
    unittest.main()
