#!/usr/bin/env python3
from .common import EmulationContext

import logging
from math import ceil, log2

from pwn import asm
from unicorn import Uc, UcError, UC_HOOK_CODE

log = logging.Logger(__name__)


class X86EmulationContext(EmulationContext):
    GPR_16 = ['ax', 'bx', 'cx', 'dx', 'si', 'di']
    GPR_32 = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']
    GPR_64 = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8',
              'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

    def __init__(self) -> None:
        super().__init__()
        self._mode = '64'
        self._registers = self.register_consts()
    
    def allowed_registers(self) -> list[str]:
        # Technically we only need ymm since xmm is the lower 128-bit version
        ymms = [f'ymm{i}' for i in range(32)]
        # UE has no support for zmm yet
        if self.mode == '64':
            return self.GPR_64 + ymms
        if self.mode == '32':
            return self.GPR_32 + ymms
        if self.mode == '16':
            return self.GPR_16
        raise ValueError(f"Mode not supported: {self.mode}")
    
    def register_size(self, name: str) -> tuple[int, ...]:
        if name in self.GPR_16:
            return (2,)
        if name in self.GPR_32:
            return (4,)
        if name in self.GPR_64:
            return (8,)
        if name.startswith('xmm'):
            return (16,)
        if name.startswith('ymm'):
            return (32,)
        if name.startswith('zmm'):
            return (64,)
        raise ValueError(f"Register size not known: {name}")
    
    def make_emulator(self, sample: bytes, stack_size_mb: int = 1) -> Uc:
        emulator = Uc(self.arch_const, self.mode_const)

        MiB = 1024 * 1024
        # round to nearest MiB; UE/Qemu has some weird alignment requirement
        mem_size = ceil(len(sample) / MiB) * MiB + stack_size_mb * MiB
        bootstrap_size = 0x100
        bootstrap_base = self.PROGRAM_BASE + mem_size - bootstrap_size
        stack_base = bootstrap_base - 0x10
        # make sure stack is 16-byte aligned in case we change the default program_base
        stack_base -= stack_base % 0x10
        emu_start = bootstrap_base
        emu_end = bootstrap_base + bootstrap_size

        bootstrap: bytes = asm(f'call 0x{self.PROGRAM_BASE:x}',
                                     vma=bootstrap_base,
                                     arch='amd64',
                                     os='linux')
        bootstrap = bootstrap.ljust(bootstrap_size, b'\x90')

        # TODO: create one mmap for program image (R-X) and one mmap for stack (RW-)
        emulator.mem_map(self.PROGRAM_BASE, mem_size)
        emulator.mem_write(self.PROGRAM_BASE, sample)
        emulator.mem_write(bootstrap_base, bootstrap)

        def stack_setup(emulator: Uc, address, size, user_data):
            emulator.reg_write(self._registers['rsp'], stack_base)

        emulator.hook_add(UC_HOOK_CODE, stack_setup, None, emu_start, emu_start)

        return emulator, emu_start, emu_end

    def dump_registers(self, emulator: Uc) -> dict[str, any]:
        reg_values = {}
        allowed_regs = self.allowed_registers()
        for regname, regconst in self.register_consts().items():
            if regname not in allowed_regs:
                continue
            try:
                value = emulator.reg_read(regconst)
                reg_values[regname] = value
            except UcError as e:
                log.warning(f'Failed to read register {regname}: {e}')
                reg_values[regname] = None
        return reg_values

    @property
    def arch(self) -> str:
        return 'x86'

    @property
    def mode(self) -> str:
        return self._mode

    @mode.setter
    def mode(self, value):
        if value in ['64', '32']:
            self._mode == value
        else:
            raise ValueError(f"Mode not supported for x86: {value}")

    @property
    def pc(self) -> str:
        if self.mode == '64':
            return 'rip'
        elif self.mode == '32':
            return 'eip'
        else:
            return 'ip'

    @property
    def pc_const(self) -> int:
        return self._registers[self.pc]
