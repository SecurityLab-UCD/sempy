#!/usr/bin/env python3
import logging

from pwn import asm
from unicorn import UC_HOOK_CODE, Uc
from unicorn.unicorn_const import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE

from ..emulation import (
    EmulationContext,
    MemVar,
    RandMemVar,
    Register,
    SExtRegister,
    ZExtRegister,
    VarAttr,
    Variable,
    Program,
)

log = logging.Logger(__name__)


class X86EmulationContext(EmulationContext):
    GPR_8 = ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh"]
    GPR_16 = ["ax", "bx", "cx", "dx", "si", "di"]
    GPR_32 = ["eax", "ebx", "ecx", "edx", "esi", "edi"]
    GPR_64 = [
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ]

    def __init__(self) -> None:
        super().__init__()
        self._mode = "64"
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
        self._rsp = stack_map[0] + stack_map[1]

        self._variables: list[Variable] = []
        self._result_variables: list[Variable] = []

    def _make_stack_arg(self, size=None):
        # NOTE: push defaults to word size (x64 => 64 bits)
        if not size or size <= int(self._mode):
            size_on_stack = int(self._mode)
        else:
            size_on_stack = size
        self._rsp -= size_on_stack
        return MemVar(self._rsp, size, self, VarAttr.MEMORY | VarAttr.FUNCTION_ARG)

    def set_fn(self, ret_ty: str, arg_tys: list[str]):
        # TODO: handle mode 32
        stack_base, stack_size, _ = self._mmaps["stack"]
        self._rsp = stack_base + stack_size

        # integer / pointer arguments from left to right
        arg_gprs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        non_arg_gprs = list(set(self.GPR_64) - set(arg_gprs))
        arg_gprs = [Register(name, self) for name in arg_gprs]
        non_arg_gprs = [Register(name, self) for name in non_arg_gprs]
        # TODO: change to zmm when UE supports it
        sse_regs = [f"ymm{i}" for i in range(32)]
        sse_regs = [Register(name, self) for name in sse_regs]

        # index to current unused register in arg_gprs (int/ptr only)
        unused_gpr = 0

        stack_vars: list[MemVar] = []
        heap_vars: list[RandMemVar] = []

        def size_of(arg_type: str):
            return (int(arg_type[1:]) + 7) // 8

        for arg_type in arg_tys:
            arg_attr = arg_type.split(":")[1] if ":" in arg_type else ""
            arg_type = arg_type.split(":")[0]

            # NOTE: Refer to https://www.uclibc.org/docs/psABI-x86_64.pdf for ABI
            # HACK: For now, assume that there won't be enough floating pointer & vector
            # arguments to fill all SSE registers.
            if arg_type[0] not in ["i", "p", "u"]:
                continue
            if unused_gpr < len(arg_gprs):
                # NOTE: Also assuming that i<size> is within word size
                arg_gprs[unused_gpr].attr |= VarAttr.FUNCTION_ARG
                if arg_type[0] == "p":
                    arg_gprs[unused_gpr].attr |= VarAttr.PTR
                    # ceil arg_type bit size to byte size
                    heap_vars.append(
                        RandMemVar(arg_gprs[unused_gpr], size_of(arg_type), self)
                    )
                elif arg_attr == "s":
                    arg_gprs[unused_gpr] = SExtRegister(
                        arg_gprs[unused_gpr]._reg, size_of(arg_type), self
                    )
                elif arg_attr == "z":
                    arg_gprs[unused_gpr] = ZExtRegister(
                        arg_gprs[unused_gpr]._reg, size_of(arg_type), self
                    )
                unused_gpr += 1
            else:
                stack_var = self._make_stack_arg(int(self._mode))
                stack_vars.append(stack_var)
                if arg_type[0] == "p":
                    stack_var.attr |= VarAttr.PTR
                    heap_vars.append(RandMemVar(stack_var, size_of(arg_type), self))

        # NOTE: Order is important. RandMemVars depend on pointer values of arg_gprs.
        # FIXME: add stack randomization to emulate undef behavior
        self._variables = arg_gprs + sse_regs + non_arg_gprs + stack_vars + heap_vars

        # Registers that may contain return values: rax, rdx, ymm0
        # Don't need the exact Variable objects created earlier.
        if ret_ty[0] in ["i", "u"]:
            size = int(ret_ty[1:])
            reg = ""
            match size:
                case 8:
                    reg = "al"
                case 16:
                    reg = "ax"
                case 32:
                    reg = "eax"
                case _:
                    reg = "rax"
            self._result_variables = [Register(reg, self)]
        elif ret_ty[0] in ["v", "f"]:
            self._result_variables = [Register("ymm0", self)]
        elif ret_ty[0] == "p":
            self._result_variables = [
                RandMemVar(Register("rax", self), int(ret_ty[1:]), self)
            ]
        else:
            log.warning(f"Unidentified return type {ret_ty}, defaulting to int")
            self._result_variables = [Register("rax", self)]
        self._result_variables.extend(heap_vars)

    def allowed_registers(self) -> list[str]:
        # Technically we only need ymm since xmm is the lower 128-bit version
        ymms = [f"ymm{i}" for i in range(32)]
        # UE has no support for zmm yet
        if self.mode == "64":
            return self.GPR_64 + ymms
        if self.mode == "32":
            return self.GPR_32 + ymms
        if self.mode == "16":
            return self.GPR_16
        raise ValueError(f"Mode not supported: {self.mode}")

    def register_size(self, name: str) -> int:
        if name in self.GPR_8:
            return 1
        if name in self.GPR_16:
            return 2
        if name in self.GPR_32:
            return 4
        if name in self.GPR_64:
            return 8
        if name.startswith("xmm"):
            return 16
        if name.startswith("ymm"):
            return 32
        if name.startswith("zmm"):
            return 64
        raise ValueError(f"Register size not known: {name}")

    def make_emulator(self, program: Program) -> tuple[Uc, int, int]:
        # TODO: track memory accesses (esp. writes) and add to self._result_variables
        emulator = Uc(self.arch_const, self.mode_const)

        bootstrap_size = 0x100
        bootstrap_base = self._mmaps["bootstrap"][0]
        emu_start = bootstrap_base
        emu_end = bootstrap_base + bootstrap_size

        bootstrap: bytes = asm(
            f"call 0x{self.program_base + program.fn_start_offset:x}",
            vma=bootstrap_base,
            arch="amd64",
            os="linux",
        )
        assert len(bootstrap) < bootstrap_size
        bootstrap = bootstrap.ljust(bootstrap_size, b"\x90")

        for base, size, perms in self._mmaps.values():
            emulator.mem_map(base, size, perms)

        assert self._mmaps["program"][1] >= len(program.image)
        emulator.mem_write(self.program_base, program.image)
        emulator.mem_write(bootstrap_base, bootstrap)

        def stack_setup(emulator: Uc, address, size, user_data):
            emulator.reg_write(self.register_consts["rsp"], self._rsp)

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
        return "x86"

    @property
    def mode(self) -> str:
        return self._mode

    @mode.setter
    def mode(self, value: str):
        if value == "64":
            self._mode == value
        else:
            raise ValueError(f"Mode not supported for x86: {value}")

    @property
    def pc(self) -> str:
        if self.mode == "64":
            return "rip"
        elif self.mode == "32":
            return "eip"
        else:
            return "ip"

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
