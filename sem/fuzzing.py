#!/usr/bin/env python3
import contextlib
from glob import glob
import json
import logging
import os
import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from binascii import hexlify
from dataclasses import dataclass
from enum import IntEnum, auto
from subprocess import CompletedProcess
import tempfile

from prettytable import PrettyTable
from tqdm import tqdm
from unicorn import Uc, UcError
from unicorn.unicorn_const import *
from elftools.elf.elffile import ELFFile

from .emulation import EmulationContext, Randomizer, VarAttr, Variable, Program

log = logging.Logger(__name__, logging.INFO)


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


class RunStatus(IntEnum):
    RUN_OK = 0
    RUN_DIFF = auto()
    RUN_GEN_EXC = auto()
    RUN_TIMEOUT = auto()
    RUN_EMU_EXC = auto()


is_debug = False


def rmdir(dir: str):
    if dir and not is_debug:
        shutil.rmtree(dir, True)


def save_seed(p: Program, program_seed: int):
    """Rename a program's data dir it to program seed and return the path."""

    data_dir = p.data_dir
    dest = os.path.join(data_dir.rsplit("/", 1)[0], str(program_seed))
    shutil.rmtree(dest, ignore_errors=True)
    os.rename(data_dir, dest)
    return dest


@dataclass
class Experiment:
    """Class for testing compiler optimization passes."""

    name: str
    output_dir: str
    initial_seed: int
    program_provider: ProgramProvider
    opt_levels: set[str]
    repeat_count: int
    context: EmulationContext
    randomizer: Randomizer
    timeout: int
    debug: bool
    keep_data: bool
    dump_regs: bool

    def __post_init__(self):
        global is_debug
        os.makedirs(self.output_dir, exist_ok=True)
        self.randomizer.seed = self.initial_seed
        self._programs: list[Program] = []
        self._emulators: list[Uc] = []
        self._diff: dict[Variable, list[bytes]] = {}
        is_debug = self.debug
        if self.debug:
            log.setLevel(logging.DEBUG)
        else:
            log.setLevel(logging.CRITICAL)

    def run(self, program_seed: int = None) -> tuple[RunStatus, int]:
        """Returns (difference found, program seed)."""
        if not program_seed:
            program_seed = self.randomizer.next_round()
        else:
            self.randomizer.seed = program_seed

        try:
            self._programs = self.program_provider.get(self)
        except Exception as e:
            log.error("Program generation exception", exc_info=True)
            if is_debug:
                print(e)
            return (RunStatus.RUN_GEN_EXC, program_seed)

        #assert len(self._programs) >= 2
        self.context.set_fn(
            self._programs[0].fn_ret_type, self._programs[0].fn_arg_types
        )
        emu_infos = [self.context.make_emulator(program) for program in self._programs]
        self._emulators = [info[0] for info in emu_infos]

        for _ in range(self.repeat_count):
            self.randomizer.next_round()
            for idx, emu_info in enumerate(emu_infos):
                emulator = emu_info[0]
                self.randomizer.update(emulator, self.context)

            if self.dump_regs:
                print("Initial register dump:")
                self._dump_registers()

            for idx, emu_info in enumerate(emu_infos):
                emulator, emu_begin, emu_end = emu_info
                try:
                    self.randomizer.update(emulator, self.context)
                    emulator.emu_start(emu_begin, emu_end, self.timeout)
                    if emulator.reg_read(self.context.pc_const) != emu_end:
                        rmdir(self._programs[0].data_dir)
                        return (RunStatus.RUN_TIMEOUT, program_seed)
                except UcError as e:
                    pc = emulator.reg_read(self.context.pc_const)
                    pc -= self.context.program_base
                    if self.debug:
                        print("Exception register dump:")
                        self._dump_registers()
                        print(e)
                    # NOTE: To debug: objdump -b binary -m i386:x86-64 -D 0_out.bin -M intel
                    log.error(
                        f"Exception at PC=0x{pc:x} ({self._programs[idx].name}) with program seed {program_seed}",
                        exc_info=True,
                    )
                    rmdir(self._programs[0].data_dir)
                    return (RunStatus.RUN_EMU_EXC, program_seed)

            self._diff = self._diff_vars()
            if self.dump_regs:
                print("Final register dump:")
                self._dump_registers()
            if len(self._diff):
                dest = save_seed(self._programs[0], program_seed)
                with open(os.path.join(dest, "diff.txt"), "w") as f:
                    f.write(str(self.make_diff_table()))
                return (RunStatus.RUN_DIFF, program_seed)

        if self.keep_data:
            save_seed(self._programs[0], program_seed)
        else:
            rmdir(self._programs[0].data_dir)
        return (RunStatus.RUN_OK, program_seed)

    def _diff_vars(self, vars: list[Variable] = []) -> dict[Variable, list[bytes]]:
        """Returns the variables (result vars by default) that differ."""
        if not vars:
            vars: list[Variable] = self.context.result_variables
        diff = {}
        for var in vars:
            values = [var.get(emu) for emu in self._emulators]
            if self.program_provider.name == "mutate-csmith":
                if any(values[0] != value for value in values[1 : len(values) // 2]):
                    # Ignore cases where CSmith produced the difference
                    continue
            if all(values[0] == value for value in values[1:]):
                continue
            diff[var] = values
        return diff

    def _dump_registers(self):
        vars = self.context.variables
        table = {
            var: [var.get(emu) for emu in self._emulators]
            for var in vars
            # TODO: ignore SIMD registers ISA-agnostically
            if "ymm" not in var.name
        }
        print(self.make_diff_table(table))

    def make_diff_table(self, diff: dict[Variable, list[bytes]] = {}):
        if not diff:
            diff = self._diff
        table = PrettyTable(["Variable", *[p.name for p in self._programs]])
        for var, values in diff.items():
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
            table.add_row([f"{var.name} ({var.__class__.__name__})", *values])
        table.align = "r"
        # table.sortby = "Variable"
        return table


def get_sym_offset(elf_path, sym_name, is_fn=True):
    with open(elf_path, "rb") as file:
        elf = ELFFile(file)

        # Find the .text section
        section = None
        section_name = ".text" if is_fn else ".bss"
        for elf_section in elf.iter_sections():
            if elf_section.name == section_name:
                section = elf_section
                break

        if section is None:
            raise ValueError(
                f"The {section_name} section was not found in the ELF file."
            )

        # Find the address of the specified function
        sym_address = None
        for elf_section in elf.iter_sections():
            if elf_section.name != ".symtab":
                continue
            for symbol in elf_section.iter_symbols():
                if symbol.name == sym_name:
                    sym_address = symbol["st_value"]
                    break

        if sym_address is None:
            raise ValueError(f"Symbol '{sym_name}' not found in the symbol table.")

        # Calculate the offset from the start of section
        offset = sym_address
        if is_fn:
            offset -= section["sh_addr"]
        return offset


class CSmithProvider(ProgramProvider):
    """Generate programs with CSmith and compile with clang."""

    # TODO: change to option
    CSMITH_RUNTIME = os.path.join(os.environ["HOME"], "csmith/runtime")

    def get(self, experiment: Experiment) -> list[Program]:
        """Generate programs for all specified optimization levels."""
        with contextlib.nullcontext(
            tempfile.mkdtemp(prefix=experiment.output_dir)
        ) as tmpdir:
            # Remove `static` to make sure that function symbols are exported
            source_path = os.path.join(tmpdir, "source.c")
            self.gen_csmith_program(experiment, source_path)

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
                    ],
                    stderr=subprocess.DEVNULL,
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

                objcopy = "objcopy"
                if experiment.context.arch == 'arm64':
                    objcopy = "aarch64-linux-gnu-objcopy" 
                subprocess.run(
                    [objcopy, "-O", "binary", "-j", ".text", elf_path, bin_path]
                )
            ll_path = os.path.join(tmpdir, f"{experiment.opt_levels[0]}.ll")

            for opt_level in experiment.opt_levels:
                bin_path = os.path.join(tmpdir, f"{opt_level}.bin")
                with open(bin_path, "rb") as program:
                    # FIXME: find start address of target function
                    programs.append(
                        Program(f"O{opt_level}", program.read(), None, [], None, tmpdir)
                    )
            return programs

    def gen_csmith_program(self, experiment: Experiment, output_path: str):
        """Generate a random CSmith program and return its path."""
        csmith_proc: CompletedProcess = subprocess.run(
            [
                "csmith",
                "-s",
                str(experiment.randomizer.get()),
                "--max-funcs",
                "5",
                "--max-pointer-depth",
                "1",
                "--max-array-dim",
                "1",
                "--no-global-variables",
                "--nomain",
                "--no-checksum",
                "--no-builtins",
                "--concise",
                "--no-structs",
                "--no-unions",
            ],
            capture_output=True,
        )
        source = csmith_proc.stdout.decode("utf-8")
        source = source.replace("static ", "")
        # HACK: get simple memcpy & memset definition from csmith runtime
        source = "#define TCC\n" + source
        with open(output_path, "w") as source_file:
            source_file.write(source)

    @property
    def name(self) -> str:
        return "csmith"


class IRFuzzerProvider(ProgramProvider):
    MUTATION_ITERS = 100

    def get(self, experiment: Experiment) -> list[Program]:
        # TODO: architecture handling?
        with contextlib.nullcontext(
            tempfile.mkdtemp(prefix=experiment.output_dir)
        ) as tmpdir:
            ir_bc_path = os.path.join(tmpdir, "out.bc")
            open(ir_bc_path, "w").close()
            # NOTE: IRFuzzer & llvm-project sempy branch
            #       - no global variable src / sink
            #       - all functions in source must have definitions (so that they can be emulated)
            #       - createFunctionDefinition: ArgNum in interval of [1, 8]
            # TODO: non-zero subprocess exit code handling
            subprocess.run(
                ["MutatorDriver", ir_bc_path, str(experiment.randomizer.get())],
                env={"NUM_MUTATE": str(self.MUTATION_ITERS)},
                cwd=tmpdir,
                stderr=subprocess.DEVNULL,
            )
            ir_ll_path = os.path.join(tmpdir, "out.ll")
            subprocess.run(["llvm-dis", ir_bc_path, "-o", ir_ll_path])
            name, ret_ty, arg_tys = self._choose_ir_fn(experiment, ir_ll_path)

            programs: list[Program] = []
            for opt_level in experiment.opt_levels:
                ir_opt_ll_path = os.path.join(tmpdir, f"{opt_level}_out.ll")
                subprocess.run(
                    [
                        "opt",
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
                    f"-mtriple={arch if arch != 'x86' else 'x86_64'}--",
                    ir_opt_ll_path,
                    "-o",
                    asm_path,
                ]
                if arch == "x86":
                    llc_args.append("-mattr=+sse,+sse2")
                if arch == "arm64":
                    llc_args += ["-mattr=fp-armv8"]
                subprocess.run(llc_args)

                elf_path = os.path.join(tmpdir, f"{opt_level}_out.elf")
                subprocess.run(["as", asm_path, "-o", elf_path])

                image_path = os.path.join(tmpdir, f"{opt_level}_out.bin")
                objcopy = "objcopy"
                if experiment.context.arch == 'arm64':
                    objcopy = "aarch64-linux-gnu-objcopy"
                subprocess.run(
                    [objcopy, "-O", "binary", "-j", ".text", elf_path, image_path]
                )

                with open(image_path, "rb") as image_file:
                    image = image_file.read()
                programs.append(
                    Program(f"O{opt_level}", image, ret_ty, arg_tys, 0, tmpdir)
                )
            # TODO: make sure that addressspace is specified, so that alloca still allocates on *stack*
            #       alloca ref: https://llvm.org/docs/LangRef.html#alloca-instruction
            # TODO: llc: check if memcpy and other builtins are used
            return programs

    def _choose_ir_fn(
        self,
        experiment: Experiment,
        ir_ll_path: str,
        fn_name_regex: str = r"[a-zA-Z_][a-zA-Z_0-9]+",
    ) -> tuple[str, str, list[str]]:
        match_signature = (
            r"^define.* (?P<ret_ty>[^ ]+) @(?P<fn_name>"
            + fn_name_regex
            + r")\((?P<arg_list>.*)\) .*{"
        )
        with open(ir_ll_path, "r") as ir_ll_file:
            ir_ll_source_lines = [line.rstrip() for line in ir_ll_file.readlines()]
        last_generated_fn = None
        for line in ir_ll_source_lines:
            m = re.fullmatch(match_signature, line)
            if not m:
                continue
            fn_name = m.group("fn_name")
            ret_ty = self._parse_arg_tys(m.group("ret_ty"))[0]
            arg_list = m.group("arg_list")
            # Choose CSmith generated function only
            if not fn_name.startswith("func_"):
                continue
            last_generated_fn = (fn_name, ret_ty, self._parse_arg_tys(arg_list))
            if experiment and experiment.randomizer.choice([True, False]):
                continue
            if arg_list:
                return last_generated_fn
        if not last_generated_fn:
            raise RuntimeError("No generated functions found")
        # Settle for potentially empty parameter list
        return last_generated_fn

    def _parse_arg_tys(self, arg_list: str) -> list[str]:
        if not arg_list:
            return []
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
                arg_ty = f"v{vecsize}"

                # TODO: implement support for element size
                #   so instead of v512 we would have v16i32.
                #   This is needed to handle
                # if "signext" in arg:
                #     arg_ty += ":s"
                # elif "zeroext" in arg:
                #     arg_ty += ":z"

                arg_tys.append(arg_ty)
                continue

            match_scalar_ty = r"^([ifu]\d+|float|half|double|ptr)"
            m = re.match(match_scalar_ty, arg)
            if not m:
                raise RuntimeError(f"Cannot parse type: {arg}")

            if m.group(0) == "double":
                arg_ty = "f64"
            elif m.group(0) == "float":
                arg_ty = "f32"
            elif m.group(0) == "half":
                arg_ty = "f16"
            elif m.group(0) == "ptr":
                arg_ty = "p512"
            else:
                arg_ty = m.group(0)

            if "signext" in arg:
                arg_ty += ":s"
            elif "zeroext" in arg:
                arg_ty += ":z"

            arg_tys.append(arg_ty)

        return arg_tys

    @property
    def name(self) -> str:
        return "irfuzzer"


class MutateCSmithProvider(CSmithProvider, IRFuzzerProvider):
    """Provide programs generated by CSmith and mutated by IRFuzzer.

    Allows override certain parameters via environment variables
    - NUM_MUTATE: controls number of mutations
    - FN_INFO: override which function gets chosen and its signature
    """

    # Allow overriding number of iterations; useful for finding the
    # difference-causing iteration
    NUM_MUTATE = int(os.environ.get("NUM_MUTATE", "100"))

    def get(self, experiment: Experiment) -> list[Program]:
        """Get a list of programs (O*, O* unmutated). Deletes tmpdir if error occurs."""
        tmpdir = tempfile.mkdtemp(prefix=experiment.output_dir)
        try:
            return self._get(experiment, tmpdir)
        except:
            rmdir(tmpdir)
            raise

    def _get(self, experiment: Experiment, cwd: str) -> list[Program]:
        """Get a list of programs (O*, O* unmutated)."""

        # Generate CSmith sources
        csmith_c_path = os.path.join(cwd, "csmith.c")
        csmith_ll_path = os.path.join(cwd, "csmith.ll")
        self.gen_csmith_program(experiment, csmith_c_path)
        self._clang(csmith_c_path, csmith_ll_path)

        # Mutate .ll
        # NOTE: This has to be out.bc since that's also what IRFuzzer outputs into.
        irf_bc_path = os.path.join(cwd, "out.bc")
        subprocess.run(["llvm-as", csmith_ll_path, "-o", irf_bc_path], check=True)
        self._mutate(irf_bc_path, cwd, experiment)

        # Disassemble to choose a function
        irf_ll_path = os.path.join(cwd, "out.ll")
        subprocess.run(["llvm-dis", irf_bc_path, "-o", irf_ll_path], check=True)

        # Get override from env; useful for reproduction independent of NUM_MUTATE.
        fn_info = os.environ.get("FN_INFO", "")
        if fn_info:
            fn_info = tuple(json.loads(fn_info))
        else:
            fn_info = self._choose_ir_fn(experiment, csmith_ll_path)
        with open(os.path.join(cwd, "fn_info.json"), "w") as f:
            f.write(json.dumps(fn_info))

        # Make unmutated programs for comparison
        programs: list[Program] = []
        arch = experiment.context.arch
        triple = f"{arch if arch != 'x86' else 'x86_64'}--"
        for opt_level in experiment.opt_levels:
            csmith_elf_path = os.path.join(cwd, f"csmith.{opt_level}.elf")
            self._compile_elf(opt_level, triple, csmith_ll_path, csmith_elf_path)
            programs.append(
                self._make_program(
                    csmith_elf_path, f"O{opt_level}", fn_info, cwd, False, arch
                )
            )

        # Compile .o with EMI global
        emi_ll_path = os.path.join(cwd, "emi_false.ll")
        emi_o_path = os.path.join(cwd, "emi_false.o")
        with open(emi_ll_path, "w") as f:
            f.write("@emi_false = global i1 0")
        subprocess.run(
            [
                "llc",
                "-filetype=obj",
                f"-mtriple={triple}",
                emi_ll_path,
                f"-o",
                emi_o_path,
            ],
            check=True,
        )

        for opt_level in experiment.opt_levels:
            elf_path = os.path.join(cwd, f"{opt_level}.elf")

            self._compile_elf(opt_level, triple, irf_bc_path, elf_path, [emi_o_path])
            programs.append(
                self._make_program(
                    elf_path,
                    f"O{opt_level}*",
                    fn_info,
                    cwd,
                    True,
                    arch
                )
            )

        def rm_glob(pattern):
            files = glob(os.path.join(cwd, pattern))
            for file in files:
                os.remove(file)

        if not is_debug:
            os.remove(emi_ll_path)
            rm_glob("*.o")
            rm_glob("*.elf")
            rm_glob("*.bc")

        return programs

    def _clang(self, source: str, output: str, opt_level: str = "0"):
        """Use clang to compile source into ELF or IR file."""
        clang_args = [
            "clang",
            f"-O{opt_level}",  # don't test middle-end by default
            f"-I{self.CSMITH_RUNTIME}",
            "-nostdlib",
            "-ffreestanding",
            "-fno-builtin",
            source,
            "-o",
            output,
        ]

        if ".ll" in output:
            clang_args.extend(
                [
                    "-S",
                    "-emit-llvm",
                    "-Xclang",
                    "-disable-O0-optnone",
                ]
            )

        subprocess.run(clang_args, stderr=subprocess.DEVNULL, check=True)

    def _mutate(self, target_file: str, tmpdir: str, experiment: Experiment):
        """Mutate bitcode file via IRFuzzer"""
        assert target_file.endswith("out.bc")
        irfuzzer_env = os.environ.copy()
        irfuzzer_env["NUM_MUTATE"] = str(self.NUM_MUTATE)
        subprocess.run(
            ["MutatorDriver", target_file, str(experiment.randomizer.get())],
            env=irfuzzer_env,
            cwd=tmpdir,
            stderr=subprocess.STDOUT if is_debug else subprocess.DEVNULL,
            check=True,
        )

    def _compile_elf(
        self,
        opt_level: str,
        triple: str,
        source: str,
        output: str,
        link_with: list[str] = [],
    ):
        stderr = subprocess.STDOUT if is_debug else subprocess.DEVNULL

        source_type = ".bc" if ".bc" in source else ".ll"
        optimized_source = f"{source.replace(source_type, '')}.{opt_level}{source_type}"
        self._opt(opt_level, source, optimized_source)
        obj_file = f"{source}.{opt_level}.o"
        llc_args = [
            "llc",
            "-filetype=obj",
            f"-O{opt_level}",
            "--disable-simplify-libcalls",
            f"-mtriple={triple}",
            optimized_source,
            "-o",
            obj_file,
        ]
        if "x86" in triple:
            llc_args += ["-mattr=+sse,+sse2", "--x86-asm-syntax=intel"]
        if "arm64" in triple:
            llc_args += ["-mattr=fp-armv8"]
        subprocess.run(llc_args, stderr=stderr, check=True)

        ld = "ld"
        if "arm64" in triple:
            ld = "aarch64-linux-gnu-ld"
        subprocess.run(
            [ld, *link_with, obj_file, "-o", output, "--warn-once"],
            stderr=subprocess.DEVNULL,
            check=True,
        )

    def _opt(self, opt_level: str, source: str, output: str):
        subprocess.run(["opt", f"-O{opt_level}", source, "-o", output])

    def _make_program(
        self,
        elf_path: str,
        name: str,
        fn_info: tuple[str, str, list[str]],
        dir: str,
        has_emi: bool,
        arch: str = "x86"
    ):
        fn_name, ret_ty, arg_tys = fn_info
        fn_offset = get_sym_offset(elf_path, fn_name)
        if has_emi:
            emi_false_offset = get_sym_offset(elf_path, "emi_false", False)
        image_path = f"{elf_path}.bin"
        objcopy = "objcopy"
        if arch == 'arm64':
            objcopy = "aarch64-linux-gnu-objcopy"
        subprocess.run(
            [objcopy, "-O", "binary", "-j", ".text", elf_path, image_path], check=True
        )

        with open(image_path, "rb") as image_file:
            image = image_file.read()
            consts = {emi_false_offset: b"\x00"} if has_emi else {}
            return Program(
                f"{name}_{arch}",
                image,
                ret_ty,
                arg_tys,
                fn_offset,
                dir,
                consts,
            )

    @property
    def name(self) -> str:
        return "mutate-csmith"


class FileProvider(ProgramProvider):
    def __init__(self) -> None:
        super().__init__()
        self._filenames: list[str] = []
        self._images: list[bytes] = []
        self._arg_tys: list[str] = []
        self._offset = 0

    def set_files(self, filenames: list[str], argtys: list[str], fn_name: str):
        self._filenames = filenames
        self._images: list[bytes] = []
        for filename in self._filenames:
            with open(filename, "rb") as file:
                self._images.append(file.read())
        self._ret_ty = argtys[0]
        self._arg_tys = argtys[1:]
        self._fn_name = fn_name

    def get(self, experiment: Experiment) -> list[Program]:
        return [
            Program(
                filename,
                image,
                self._ret_ty,
                self._arg_tys,
                get_sym_offset(filename.replace(".bin", ".elf"), self._fn_name),
                None,
            )
            for filename, image in zip(self._filenames, self._images)
        ]

    @property
    def name(self) -> str:
        return "file"
