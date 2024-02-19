#!/usr/bin/env python3
import logging
import importlib
import os
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Flag, auto
from random import Random
import re
from struct import pack
import subprocess
from typing import Union, Iterable, overload

import sem.arch
from unicorn import Uc, UcError, unicorn_const

log = logging.getLogger(__name__)


@dataclass
class Program:
    name: str  # name of program (e.g. optimization level)
    image: bytes  # program image (.text section only)
    fn_ret_type: str  # function return type
    fn_arg_types: list[str]  # function argument types
    fn_start_offset: int  # address offset of the target function
    fn_name: str # funciton name
    data_dir: str  # directory where generated files are stored, delete if no difference found
    consts: dict[int, bytes] = field(default_factory=lambda: {})
    obj_name: str = None # object file name
    fn_signature: str = None # function signature
    opt_level: int = None # optimization level
    emi: bool = False # 

class ProgramContext(ABC):
    @property
    @abstractmethod
    def variables(self) -> list["Variable"]:
        """Variables that can be randomized before program execution."""
        pass

class EmulationContext(ABC):
    """An EmulationContext specifies how a sample is emulated and compared
    against others."""

    def __init__(self) -> None:
        super().__init__()
        self.__register_consts = None

    @abstractmethod
    def set_fn(self, ret_ty: str, arg_tys: list[str]) -> None:
        """Set function argument types. Calls to this function must be repeatable."""
        pass

    @property
    @abstractmethod
    def result_variables(self) -> list["Variable"]:
        """Variables used to compare program execution results."""
        pass

    @abstractmethod
    def allowed_registers(self) -> list[str]:
        """Return registers that can be randomized without causing CPU
        exception."""
        pass

    @abstractmethod
    def register_size(self, name: str) -> int:
        """Return the size of a register in bytes."""
        pass

    @abstractmethod
    def make_emulator(self, program: Program) -> tuple[Uc, int, int]:
        """Return a reusable emulator object and the start & end address for
        emulation."""
        pass

    @property
    @abstractmethod
    def arch(self) -> str:
        """Return the architecture of the context (immutable)."""
        pass

    @property
    @abstractmethod
    def mtriple(self) -> str:
        """Return the llc mtriple option of the context (immutable)."""
        pass

    @property
    @abstractmethod
    def mode(self) -> str:
        """Return the emulation mode of the context (e.g. 64)."""
        pass

    @arch.setter
    @abstractmethod
    def mode(self, value: str):
        """Modify the emulation mode of the context."""
        pass

    @property
    def arch_const(self) -> int:
        """Return the UE constant (UC_ARCH_*) associated with self.arch."""
        return getattr(unicorn_const, f"UC_ARCH_{self.arch.upper()}")

    @property
    def mode_const(self) -> int:
        """Return the UE constant (UC_MODE_*) associated with self.mode."""
        return getattr(unicorn_const, f"UC_MODE_{self.mode.upper()}")

    @property
    @abstractmethod
    def pc(self) -> str:
        """Return the name of program counter register."""
        pass

    @property
    @abstractmethod
    def pc_const(self) -> int:
        """Return the UE constant associated with self.pc."""
        pass

    @property
    @abstractmethod
    def ptr_range(self) -> tuple[int, int]:
        """Return a 16-byte aligned range of valid heap ptr values."""
        pass

    @property
    @abstractmethod
    def program_base(self) -> int:
        """Return the address where the program image is located."""
        pass

    @property
    def register_consts(self) -> dict[str, int]:
        """Return the constants (UC_<ARCH>_REG_*) associated with all registers."""
        if self.__register_consts:
            return self.__register_consts
        # get the unicorn.<arch>_consts submodule
        target_const = None
        try:
            target_const = importlib.import_module(
                f".{self.arch.lower()}_const", "unicorn"
            )
        except ModuleNotFoundError:
            log.critical(f"Architecture {self.arch} not found!", exc_info=True)
            exit(1)

        # extract all register names & enum value
        registers = {}
        for name, value in target_const.__dict__.items():
            if "_REG_" not in name:
                continue
            prefix = f"UC_{self.arch.upper()}_REG_"
            regname = name[len(prefix) :].lower()
            if regname in ["invalid", "ending"]:
                continue
            registers[regname] = value

        self.__register_consts = registers
        return self.__register_consts

    @staticmethod
    def get(arch: str, mode: str) -> "EmulationContext":
        """Get first-available context for given arch and mode."""
        # Run the subclass definitions
        archs = [name for _, name, _ in pkgutil.iter_modules(sem.arch.__path__)]
        for ar in archs:
            importlib.import_module(f"sem.arch.{ar}")
        # Find matching subclass
        for Context in EmulationContext.__subclasses__():
            try:
                context = Context()
                if context.arch != arch:
                    continue
                # check if mode is supported by this context
                context.mode = mode
                return context
            except Exception as e:
                print(e)
        raise ValueError(f"No available emulation context for arch={arch} mode={mode}")


class Randomizer(ABC):
    @abstractmethod
    def update(self, emulator: Uc, context: EmulationContext):
        """Update register values or memory content.

        Note that each call to update() must use the same seed and produce the
        same sequence of numbers until next_round() is called. This is so that
        each sample gets the same register inputs for each round of emulation.
        This method also updates last_seed."""
        pass

    @abstractmethod
    def get(self) -> int:
        """Return a random int"""
        pass

    @abstractmethod
    def choice(self, obj: Iterable) -> any:
        """Choose an element from an iterable"""
        pass

    @property
    @abstractmethod
    def last_seed(self) -> Union[int, None]:
        """Get seed used for the last update() call."""
        pass

    @property
    @abstractmethod
    def seed(self):
        """Get the seed used for future update() calls."""
        pass

    @seed.setter
    @abstractmethod
    def seed(self, value):
        """Set the seed to use for future update() calls."""
        pass

    @abstractmethod
    def next_round(self) -> int:
        """Set the next random number as the new seed and return it.
        Use when done with a single round of emulation (i.e. emulated every sample once).
        """
        pass


class NativeContext(ProgramContext):
    def __init__(self) -> None:
        super().__init__()
        self._variables: list[NativeVariable] = []
        self._result_variables: list[NativeVariable] = []

    def run_program(self, program: Program, repeat: int, timeout: int) -> str:
        driver_file_name = f"{program.data_dir}/driver_{repeat}.c"
        if not os.path.exists(driver_file_name):
            self._create_driver(program, repeat)

        clang_args = [
            "clang",
            f"{program.data_dir}/driver_{repeat}.o",
            program.obj_name,
        ]
        if program.emi:
            clang_args.append(f"{program.data_dir}/emi_false.o")
        
        executable = f"{program.data_dir}/{program.emi}_{program.opt_level}"
        clang_args.extend([            
            "-o",
            executable,
            "-no-pie"])
        subprocess.run(clang_args, stderr=subprocess.DEVNULL, check=True)  


        result = subprocess.run(f'{executable}', 
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE, 
                                text=True, 
                                check=True,
                                timeout=timeout)

        

        return result.stdout

    def _create_driver(self, program: Program, repeat: int) -> None:
        stmts = ""
        for index, var in enumerate(self._variables):
            if var.attr & VarAttr.UNSIGNED:
                stmt = f"uint{var.size * 8}_t v{index} = {var.val};\n"
            else:
                stmt = f"int{var.size * 8}_t v{index} = {var.val};\n"
            if var.attr & VarAttr.PTR:
                if var.attr & VarAttr.UNSIGNED:
                    stmt += f"uint{var.size * 8}_t* p{index} = &v{index};\n"
                else:
                    stmt += f"int{var.size * 8}_t* p{index} = &v{index};\n"
            stmts += stmt

        args = ""
        for index, var in enumerate(self._variables):
            if var.attr & VarAttr.PTR:
                args += f"p{index}, "
            else:
                args += f"v{index}, "
        if len(args) > 0:
            args = args[:-2]

        if len(self._result_variables) > 0:
            stmts += f"{self._parse_c_ty(self._result_variables[0])} res = {program.fn_name}({args});\n"
        else:
            stmts += f"{program.fn_name}({args});\n"

        # if not void type
        if len(self._result_variables) > 0:
            stmts += f"printf(\"%\" {self._parse_printf_ty(self._result_variables[0])} \"\\n\", {'*' if self._result_variables[0].attr & VarAttr.PTR else ''} res);\n"

        for index, arg in enumerate(self._variables):
            if arg.attr & VarAttr.PTR:
                stmts += f"printf(\"%\" {self._parse_printf_ty(arg)} \"\\n\", *p{index});\n"


        driver_code = f"""
#include "csmith.h"
#include <inttypes.h>
        
{program.fn_signature};

{self._parse_c_ty(self._result_variables[0]) if len(self._result_variables) > 0 else "void"} main()
{{
    {stmts}
}}

"""

        # Open the file in write mode and write the content
        driver_file_name = f"{program.data_dir}/driver_{repeat}.c"
        with open(driver_file_name, "w") as c_file:
            c_file.write(driver_code)

        clang_args = [
            "clang",
            "-c",
            f"driver_{repeat}.c",
            "-o",
            f"driver_{repeat}.o" 
        ]
        subprocess.run(clang_args, stderr=subprocess.DEVNULL, check=True, cwd=program.data_dir)

        
    def set_fn(self, program: Program) -> None:
        pattern = re.compile(r'(?P<return_type>.+)\s+' + program.fn_name + r'\((?P<params>[^)]*)\)')
        c_file_path = os.path.join(program.data_dir, "csmith.c")
        with open(c_file_path, "r") as c_file:
            c_source_lines = [line.rstrip() for line in c_file.readlines()]

        for line in c_source_lines:
            m = re.fullmatch(pattern, line)
            if not m:
                continue
            program.fn_signature = line
            self._result_variables = self._parse_arg_tys(m.group("return_type"))   
            self._variables = self._parse_arg_tys(m.group("params"))
            for var in self._variables:
                if var.attr & VarAttr.PTR:
                    self._result_variables.append(var)


    def _parse_arg_tys(self, arg_list: str) -> list["NativeVariable"]:
        if not arg_list:
            return []
        args: list[str] = [ty.strip() for ty in arg_list.split(sep=",")]
        native_vars: list[NativeVariable] = []
        for arg in args:
            arg_split = arg.split()

            if arg_split[0] == 'const':
                arg_split.remove(arg_split[0])

            ty = arg_split[0]
            is_pointer = False
            arg_split.remove(ty)

            # pointer type
            if len(arg_split) >= 1 and arg_split[0] == '*':
                is_pointer = True

            match = re.search(r'([a-zA-Z]+)(\d+)_t', ty)
            if match:
                ty_attr = match.group(1)
                ty_size = int(match.group(2))
            else:
                # void return type
                return []
            native_var_attr = VarAttr.NATIVE
            if ty_attr == "uint":
                native_var_attr = native_var_attr | VarAttr.UNSIGNED
            if is_pointer:
                native_var_attr = native_var_attr | VarAttr.PTR

            native_var_size = int(ty_size)
            native_vars.append(NativeVariable(
                native_var_attr, native_var_size, self))
        return native_vars

    def _parse_c_ty(self, type: "NativeVariable") -> str:
        if isinstance(type, NativeVariable) and type.size == 1 and type.attr & VarAttr.UNSIGNED:
            ty = "uint8_t"
        elif isinstance(type, NativeVariable) and type.size == 2 and type.attr & VarAttr.UNSIGNED:
            ty =  "uint16_t"
        elif isinstance(type, NativeVariable) and type.size == 4 and type.attr & VarAttr.UNSIGNED:
            ty =  "uint32_t"
        elif isinstance(type, NativeVariable) and type.size == 8 and type.attr & VarAttr.UNSIGNED:
            ty =  "uint64_t"
        elif isinstance(type, NativeVariable) and type.size == 1 and type.attr:
            ty =  "int8_t"
        elif isinstance(type, NativeVariable) and type.size == 2 and type.attr:
            ty =  "int16_t"
        elif isinstance(type, NativeVariable) and type.size == 4 and type.attr:
            ty =  "int32_t"
        elif isinstance(type, NativeVariable) and type.size == 8 and type.attr:
            ty =  "int64_t"
        if isinstance(type, NativeVariable) and type.attr & VarAttr.PTR:
            ty += " * "
        return ty

    def _parse_printf_ty(self, type: "NativeVariable") -> str:
        if isinstance(type, NativeVariable) and type.size == 1 and type.attr & VarAttr.UNSIGNED:
            return "PRIu8"
        if isinstance(type, NativeVariable) and type.size == 2 and type.attr & VarAttr.UNSIGNED:   
            return "PRIu16"
        if isinstance(type, NativeVariable) and type.size == 4 and type.attr & VarAttr.UNSIGNED:
            return "PRIu32"
        if isinstance(type, NativeVariable) and type.size == 8 and type.attr & VarAttr.UNSIGNED:
            return "PRIu64"
        if isinstance(type, NativeVariable) and type.size == 1 and type.attr:
            return "PRId8"
        if isinstance(type, NativeVariable) and type.size == 2 and type.attr:
            return "PRId16"
        if isinstance(type, NativeVariable) and type.size == 4 and type.attr:
            return "PRId32"
        if isinstance(type, NativeVariable) and type.size == 8 and type.attr:
            return "PRId64"
        

    @staticmethod
    def get() -> "NativeContext":
        return NativeContext()

    @property
    def variables(self) -> list["NativeVariable"]:
        return self._variables

class VarAttr(Flag):
    REGISTER = auto()
    MEMORY = auto()
    FUNCTION_ARG = auto()
    PTR = auto()
    NATIVE = auto()
    UNSIGNED = auto()


class Variable(ABC):
    def __init__(self, context: ProgramContext, attr: VarAttr) -> None:
        super().__init__()
        self._context: ProgramContext = context
        self._attr = attr

    @abstractmethod
    def set(data: bytes, emulator: Uc = None) -> bool:
        pass

    @abstractmethod
    def get(self, emulator: Uc) -> bytes:
        pass

    @property
    @abstractmethod
    def name(self):
        pass

    @property
    @abstractmethod
    def size() -> int:
        pass

    @property
    def attr(self) -> VarAttr:
        return self._attr

    @attr.setter
    def attr(self, new_attr: VarAttr):
        self._attr = new_attr


class Register(Variable):
    def __init__(
        self, name: str, context: EmulationContext, attr: VarAttr = VarAttr.REGISTER
    ) -> None:
        super().__init__(context, attr)
        self._reg: str = name

    def set(self, data: bytes, emulator: Uc) -> bool:
        if len(data) != self.size:
            return False
        try:
            emulator.reg_write(
                self._context.register_consts[self._reg], int.from_bytes(data, "big")
            )
            return True
        except UcError:
            return False

    def get(self, emulator: Uc):
        true_size = self._context.register_size(self._reg)
        return emulator.reg_read(self._context.register_consts[self._reg]).to_bytes(
            true_size, "big"
        )

    @property
    def name(self):
        return self._reg

    @property
    def size(self):
        return self._context.register_size(self._reg)


class MemVar(Variable):
    def __init__(
        self, addr: int, size: int, context: EmulationContext, attr=VarAttr.MEMORY
    ) -> None:
        super().__init__(context, attr)
        self._size = size
        self._addr = addr

    def set(self, data: bytes, emulator: Uc) -> bool:
        if len(data) != self.size:
            return False
        try:
            emulator.mem_write(self._addr, data)
        except UcError:
            return False

    def get(self, emulator: Uc):
        return emulator.mem_read(self._addr, self.size)

    @property
    def name(self):
        return hex(self._addr)

    @property
    def size(self):
        return self._size


class RandMemVar(Variable):
    def __init__(
        self,
        addr: Variable,
        size: int,
        context: EmulationContext,
        attr: VarAttr = VarAttr.MEMORY,
    ) -> None:
        super().__init__(context, attr)
        self._addr_src = addr
        self._addr = None
        self._size = size

    def set(self, data: bytes, emulator: Uc) -> bool:
        if len(data) != self.size:
            return False
        try:
            if isinstance(self._addr_src, MemVar) or \
                isinstance(self.addr_src, RandMemVar):
                self._addr = int.from_bytes(self._addr_src.get(emulator), "little")
            else:
                self._addr = int.from_bytes(self._addr_src.get(emulator), "big")
            emulator.mem_write(self._addr, data)
        except UcError:
            return False

    def get(self, emulator: Uc):
        if not self._addr:
            if isinstance(self._addr_src, MemVar) or \
                isinstance(self.addr_src, RandMemVar):
                self._addr = int.from_bytes(self._addr_src.get(emulator), "little")
            else:
                self._addr = int.from_bytes(self._addr_src.get(emulator), "big")
        if self._addr == 0:
            return None
        return emulator.mem_read(self._addr, self._size)

    @property
    def name(self):
        return f"[{self._addr_src.name}] ({self.size})"

    @property
    def size(self):
        return self._size
    
    @property
    def addr_src(self):
        return self._addr_src

class ZExtRegister(Register):
    def __init__(
        self,
        name: str,
        new_size: int,
        context: EmulationContext,
        attr: VarAttr = VarAttr.REGISTER,
    ) -> None:
        super().__init__(name, context, attr)
        self._new_size = new_size

    def set(self, data: bytes, emulator: Uc) -> bool:
        if len(data) != self.size:
            return False
        data = int.from_bytes(data, "big")
        try:
            emulator.reg_write(self._context.register_consts[self._reg], data)
            return True
        except UcError:
            return False

    @Register.size.getter
    def size(self):
        return self._new_size


class SExtRegister(Register):
    def __init__(
        self,
        name: str,
        new_size: int,
        context: EmulationContext,
        attr: VarAttr = VarAttr.REGISTER,
    ) -> None:
        super().__init__(name, context, attr)
        self._new_size = new_size

    def _sext(self, value):
        sign_bit = 1 << (super().size * 8 - 1)
        return (value & (sign_bit - 1)) - (value & sign_bit)

    def set(self, data: bytes, emulator: Uc) -> bool:
        if len(data) != self.size:
            return False
        data = self._sext(int.from_bytes(data, "big", signed=True))
        try:
            emulator.reg_write(self._context.register_consts[self._reg], data)
            return True
        except UcError:
            return False

    @Register.size.getter
    def size(self):
        return self._new_size


class DefaultRandomizer(Randomizer):
    """A simple randomizer that just update variables with random bytes. Handles
    VarAttr.PTR."""

    def __init__(self, seed: int = 0) -> None:
        super().__init__()
        self._random = Random()
        self.seed = seed
        self._last_seed = None

    def update(self, emulator: Uc, context: EmulationContext):
        self._last_seed = self.seed
        for variable in context.variables:
            data = self._random.randbytes(variable.size)
            if variable.attr & VarAttr.PTR and \
                variable.attr & (VarAttr.MEMORY | VarAttr.REGISTER):
                # TODO: try to prevent overlapping
                data = self._random.randrange(*context.ptr_range, 0x10)
                data = data.to_bytes(variable.size, "big")
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
    
class NativeVariable(Variable):
    def __init__(self,
                 attr: VarAttr,
                 size: int,
                 context: NativeContext) -> None:
        super().__init__(context, attr)
        self._context: NativeContext = context
        self._attr = attr
        self._size = int(size / 8)
        self._value = None

    def set(self, data: bytes, emulator: Uc = None) -> bool:
        if len(data) != self.size:
            return False
        self._value = int.from_bytes(data, "big", 
                                     signed=not (self._attr & VarAttr.UNSIGNED))


    def get(self) -> bytes:
        pass

    def name(self):
        pass

    @property
    def size(self) -> int:
        return self._size

    @property
    def attr(self) -> VarAttr:
        return self._attr
    
    @property  
    def val(self) -> int:
        return self._value

    @attr.setter
    def attr(self, new_attr: VarAttr):
        self._attr = new_attr

