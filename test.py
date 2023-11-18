import contextlib
import importlib
import logging
import os
import pkgutil
from random import Random
import shutil
import subprocess
import tempfile
import inspect
from typing import Iterable, Union
import unittest
from unicorn import Uc

print(os.getcwd())

from sem.emulation import (
    DefaultRandomizer,
    EmulationContext,
    MemVar,
    Program,
    RandMemVar,
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


class StubRandomizer(DefaultRandomizer):
    """A simple randomizer that just update variables with preset bytes. Handles
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
        vals = self._preset_vals[:]
        for variable in context.variables:
            if variable.attr & VarAttr.PTR:
                # TODO: try to prevent overlapping
                data = self._random.randrange(*context.ptr_range, 0x10)
                data = data.to_bytes(variable.size, "big")
                self._index += 1
            
            elif variable.attr & VarAttr.FUNCTION_ARG and \
                not isinstance(variable, MemVar):
                data = vals[self._index]
                data = data.to_bytes(variable.size, "big")
                del vals[self._index]

            elif variable.attr & VarAttr.FUNCTION_ARG and \
                isinstance(variable, MemVar):
                data = vals[self._index]
                data = data.to_bytes(variable.size, "little")
                del vals[self._index]


            elif isinstance(variable, RandMemVar) and \
                variable.addr_src.attr & VarAttr.FUNCTION_ARG \
                or variable.attr & VarAttr.FUNCTION_ARG:
                data = vals[0]
                data = data.to_bytes(variable.size, "little")
                del vals[0]

            else:
                data = self._random.randbytes(variable.size)
            print(f"{variable.name} {data}")
            variable.set(data, emulator)
        self.seed = self._last_seed


class TestImplementations(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)

        self.contexts = [
            EmulationContext.get("arm64", "arm"),
            EmulationContext.get("x86", "64"),
        ]

    def setup_emulations(self, testPath, presetVals):
        test_experiments = []
        test_results = []
        program_seed = 10

        for context in self.contexts:
            testProgramProvider = TestProgramProvider(testPath, context)
            testExperiment = Experiment(
                f"test_{context.arch}_{context.mode}",
                out_dir,
                program_seed,
                testProgramProvider,
                [],
                1,
                context,
                StubRandomizer(seed = 0, preset_vals=presetVals),
                int(0.5 * UC_SECOND_SCALE),
                True
            )
            test_experiments.append(testExperiment)

        for test in test_experiments:
            test.run(program_seed)
            res_vars = test.context.result_variables
            test_results.append([
                int.from_bytes(res_vars[0].get(emu), byteorder='big') 
                for emu in test._emulators])   

        compile_command = ['gcc', testPath, '-o', 'test']
        subprocess.run(compile_command, check=True)

        # Execute the compiled program and collect its output
        execution_command = ['./test']
        process = subprocess.Popen(
            execution_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        output, _ = process.communicate()
        #shutil.rmtree('./test')

        # Split the output into lines and store them in a list
        output_lines = [(int)(output.splitlines()[0])]

        test_results.append(output_lines)

        self.assertTrue(self.are_all_elements_same(test_results))
    
    def are_all_elements_same(self, input_list):
        return all(elem == input_list[0] for elem in input_list[1:])


    def test_pointer_args(self):
        self.setup_emulations("./testcases/test_pointer_args.c", [2000000])
        return

    def test_stack_args(self):
        self.setup_emulations("./testcases/test_stack_args.c", 
                              [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

if __name__ == '__main__':
    unittest.main()
