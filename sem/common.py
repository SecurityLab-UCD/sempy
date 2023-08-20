#!/usr/bin/env python3
import logging
import importlib
from typing import Union
from abc import ABC, abstractmethod
from random import Random

from unicorn import Uc, UcError, unicorn_const

log = logging.getLogger(__name__)


class EmulationContext(ABC):
    """An EmulationContext specifies how a sample is emulated and compared
    against others."""

    PROGRAM_BASE = 0x10000000

    @abstractmethod
    def allowed_registers(self) -> list[str]:
        """Return registers that can be randomized without causing CPU
        exception."""
        pass
    
    @abstractmethod
    def register_size(self, name: str) -> tuple[int, ...]:
        """Return the dimensions of a register.
        
        Each tuple element specifies a size in bytes. Plain scalar and vector
        registers uses one element, whereas special registers e.g. FP0 may
        require more."""
        pass
    
    def dump_registers(self, emulator: Uc) -> dict[str, any]:
        """Dump all allowed register values."""
        reg_values = {}
        for regname, regconst in self.register_consts().items():
            try:
                value = emulator.reg_read(regconst)
                reg_values[regname] = value
            except UcError as e:
                log.warning(f'Failed to read register {regname}: {e}')
        return reg_values
    
    @abstractmethod
    def make_emulator(self, sample: bytes, stack_size_mb: int = 1) -> tuple[Uc, int, int]:
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
    def mode(self) -> str:
        """Return the emulation mode of the context (e.g. 64)."""
        pass
    
    @arch.setter
    @abstractmethod
    def mode(self, value) -> str:
        """Modify the emulation mode of the context."""
        pass

    @property
    def arch_const(self) -> int:
        """Return the UE constant (UC_ARCH_*) associated with self.arch."""
        return getattr(unicorn_const, f'UC_ARCH_{self.arch.upper()}')

    @property
    def mode_const(self) -> int:
        """Return the UE constant (UC_MODE_*) associated with self.mode."""
        return getattr(unicorn_const, f'UC_MODE_{self.mode.upper()}')
    
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

    def register_consts(self) -> dict[str, int]:
        """Return the constants (UC_<ARCH>_REG_*) associated with all registers."""
        # get the unicorn.<arch>_consts submodule
        target_const = None
        try:
            target_const = importlib.import_module(
                f'.{self.arch.lower()}_const', 'unicorn')
        except ModuleNotFoundError:
            log.critical(f'Architecture {self.arch} not found!', exc_info=True)
            exit(1)
        
        # extract all register names & enum value
        registers = {}
        for name, value in target_const.__dict__.items():
            if '_REG_' not in name:
                continue
            prefix = f'UC_{self.arch.upper()}_REG_'
            regname = name[len(prefix):].lower()
            if regname in ['invalid', 'ending']:
                continue
            registers[regname] = value

        return registers

    @staticmethod
    def get(arch: str, mode: str) -> 'EmulationContext':
        """Get first-available context for given arch and mode."""
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

        Note that each call to update() must use the same seed until reseed() is
        called. This is so that each sample gets the same register inputs for
        each round of emulation. This method also updates last_seed."""
        pass

    @property
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
    def next_round(self):
        """Set the next random number as the new seed. Use when done with a
        single round of emulation (i.e. emulated every sample once)."""
        pass

    
class RegisterRandomizer(Randomizer):

    def __init__(self, seed: int=0) -> None:
        super().__init__()
        self._random = Random()
        self.seed = seed
        self._last_seed = None

    def update(self, emulator: Uc, context: EmulationContext):
        registers = context.register_consts()
        registers = { regname: registers[regname]
                      for regname in context.allowed_registers() }
        self._last_seed = self.seed
        for regname, regenum in registers.items():
            try:
                value = []
                size = context.register_size(regname)
                for elemsize in size:
                    randbytes = self._random.randbytes(elemsize)
                    value.append(int.from_bytes(randbytes, 'big'))
                if len(value) == 1:
                    value = value[0]
                else:
                    value = tuple(value)
                emulator.reg_write(regenum, value)
            except Exception as e:
                log.warning(f'Failed to write register {regname}: {e}')
        self.seed = self.seed


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

    def next_round(self):
        self.seed = self._random.randint(0, 2 ** 64 - 1)
