#!/usr/bin/env python3
import logging
from math import ceil, log2

from pwn import asm
from unicorn import UC_HOOK_CODE, Uc
from unicorn.unicorn_const import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE
from unicorn import *
from unicorn.arm64_const import *

from ..emulation import (
    EmulationContext,
    MemVar,
    RandMemVar,
    Register,
    VarAttr,
    Variable,
    Program,
)

log = logging.Logger(__name__)

class Arm64EmulationContext(EmulationContext):
    _GPR_INT_32 = [f'w{i}' for i in range(31)]
    _GPR_INT_64 = [f'x{i}' for i in range(31)]
    _FPR_8 = [f'b{i}' for i in range(31)]
    _FPR_16 = [f'h{i}' for i in range(31)]
    _FPR_32 = [f's{i}' for i in range(31)]
    _FPR_64 = [f'd{i}' for i in range(31)]
    _FPR_128 = [f'q{i}' for i in range(31)]

    def __init__(self) -> None:
        super().__init__()
        self._mode = "arm"
        # 1 MB alignment required by UE/QEMU
        map_size = 0x1000000
        self._mmaps: dict[str, tuple[int, int, int]] = {
            "bootstrap": (map_size, map_size, UC_PROT_READ | UC_PROT_EXEC),
            "stack": (map_size * 2, map_size, UC_PROT_READ | UC_PROT_WRITE),
            "heap": (map_size * 3, map_size, UC_PROT_READ | UC_PROT_WRITE),
            # NOTE: assume max program size = 1MB for now
            "program": (map_size * 4, map_size, UC_PROT_READ | UC_PROT_EXEC),
        }

        stack_map = self._mmaps["stack"]
        self._sp = stack_map[0] + stack_map[1]

        self._variables: list[Variable] = []
        self._result_variables: list[Variable] = []

     
    
    def set_fn(self, ret_ty: str, arg_tys: list[str]):
        stack_map = self._mmaps["stack"]
        self._sp = stack_map[0] + stack_map[1]
        all_gprs = [Register(gpr, self) for gpr in self._GPR_INT_64]
        all_fprs = [Register(fpr, self) for fpr in self._FPR_128]
        gprs_arg: list[Register] = []

        stack_vars: list[MemVar] = []
        heap_vars: list[RandMemVar] = []

        stack_vars_space = max((len(arg_tys) - 8) * 8, 0)
        self._sp -= stack_vars_space

        for idx, arg in enumerate(arg_tys):
            ## TODO: what is "u"
            register = None
            if arg[0] not in ["i", "p", "u"]:
                continue
            if idx < 8:
                if arg[0] == "p":
                    register = Register(f"x{idx}", self)
                    register.attr |= VarAttr.PTR
                    # ceil arg_type bit size to byte size
                    heap_vars.append(
                        RandMemVar(
                            register, (int(arg[1:]) + 7) // 8, self
                        )
                    )
                elif int(arg[1:]) > 32:
                    register = Register(f"x{idx}", self)
                else: 
                    register = Register(f"w{idx}", self)
                register.attr |= VarAttr.FUNCTION_ARG
                gprs_arg.append(register)
            else:
                stack_var = MemVar(self._sp + (idx - 8) * 8, 
                                   8, self, VarAttr.MEMORY | VarAttr.FUNCTION_ARG)
                stack_vars.append(stack_var)
                if arg[0] == "p":
                    stack_var.attr |= VarAttr.PTR
                    heap_vars.append(
                        RandMemVar(stack_var, (int(arg[1:]) + 7) // 8, self)
                    )

        # NOTE: Order is important. RandMemVars depend on the corresponding args.
        # TODO: 1. I need help with understanding the note
        #       2. SSE equivalent in aarch64?
        self._variables = all_gprs + all_fprs + gprs_arg + stack_vars + heap_vars

        if ret_ty[0] in ["i", "u"]:
            size = int(ret_ty[1:])
            if size <= 32:
                # w0
                self._result_variables = [Register("w0", self)]
            else:
                # x0
                self._result_variables = [Register("x0", self)]
        elif ret_ty[0] == "f":
            size = int(ret_ty[1:])
            if size == 8:
                self._result_variables = [Register("b0", self)]
            elif size == 16:
                self._result_variables = [Register("h0", self)]
            elif size == 32:
                self._result_variables = [Register("s0", self)]
            elif size == 64:
                self._result_variables = [Register("d0", self)]
            elif size == 128:
                self._result_variables = [Register("q0", self)]
        elif ret_ty[0] == "p":
            self._result_variables = [
                RandMemVar(Register("x0", self), int(ret_ty[1:]), self)
            ]
        elif ret_ty[0] == 'v':
            raise NotImplementedError
        else:
            log.warning(f"Unidentified return type {ret_ty}, defaulting to int")
            self._result_variables = [Register("w0", self)]
        self._result_variables.extend(heap_vars)

    def allowed_registers(self) -> list[str]:
        return [self._GPR_INT_32.join(self._GPR_INT_64)
                                .join(self._FPR_8)
                                .join(self._FPR_16)
                                .join(self._FPR_32)
                                .join(self._FPR_64)
                                .join(self._FPR_128)]

    def register_size(self, name: str) -> int:
        if name in self._GPR_INT_32:
            return 4
        if name in self._GPR_INT_64:
            return 8
        if name in self._FPR_8:
            return 1
        if name in self._FPR_16:
            return 2
        if name in self._FPR_32:
            return 4
        if name in self._FPR_64:
            return 8
        if name in self._FPR_128:
            return 16
        raise ValueError(f"Register size not known: {name}")

    def make_emulator(self, program: Program) -> tuple[Uc, int, int]:
        emulator = Uc(self.arch_const, self.mode_const)

        #bootstrap_size = 0x100
        bootstrap_base = self._mmaps["bootstrap"][0]


        bootstrap: bytes = asm(
            f"bl 0x{self.program_base - bootstrap_base + program.fn_start_offset:x}",
            vma=bootstrap_base,
            arch="aarch64",
            os="linux",
        )
        emu_start = bootstrap_base
        emu_end = bootstrap_base + len(bootstrap)

        #assert len(bootstrap) < bootstrap_size
        #bootstrap = bootstrap.ljust(bootstrap_size, b"\x90")

        for base, size, perms in self._mmaps.values():
            emulator.mem_map(base, size, perms)

        assert self._mmaps["program"][1] >= len(program.image)
        emulator.mem_write(self.program_base, program.image)
        emulator.mem_write(bootstrap_base, bootstrap)

        def stack_setup(emulator: Uc, address, size, user_data):
            emulator.reg_write(self.register_consts["sp"], self._sp)

        emulator.hook_add(UC_HOOK_CODE, stack_setup, None, emu_start, emu_start)

        return emulator, emu_start, emu_end

    @property
    def variables(self) -> list[Variable]:
        return self._variables

    @property
    def result_variables(self) -> list[Variable]:
        return self._result_variables

    @property
    def arch(self) -> str:
        return "arm64"
    
    @property
    def mtriple(self) -> str:
        return "aarch64"

    @property
    def mode(self) -> str:
        return self._mode

    @mode.setter
    def mode(self, value: str):
        return 

    @property
    def pc(self) -> str:
        return "pc"

    @property
    def pc_const(self) -> int:
        return self.register_consts[self.pc]

    @property
    def program_base(self) -> int:
        return self._mmaps["program"][0]

    @property
    def ptr_range(self) -> tuple[int, int]:
        """Return a 16-byte aligned range of valid ptr values."""
        heap_map = self._mmaps["heap"]
        return (heap_map[0], heap_map[0] + heap_map[1])
