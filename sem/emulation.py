#!/usr/bin/env python3
import logging
import importlib
import pkgutil
from enum import Flag, auto
from typing import Union, Iterable
from abc import ABC, abstractmethod
from random import Random

import sem.arch
from unicorn import Uc, UcError, unicorn_const

log = logging.getLogger(__name__)


class EmulationContext(ABC):
    """An EmulationContext specifies how a sample is emulated and compared
    against others."""

    def __init__(self) -> None:
        super().__init__()
        self.__register_consts = None

    @abstractmethod
    def set_arg_types(self, args: list[str]) -> None:
        """Set function argument types. Calls to this function must be repeatable."""
        pass

    @property
    @abstractmethod
    def variables(self) -> list["Variable"]:
        """Variables that can be randomized before program execution."""
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
    def make_emulator(self, sample: bytes) -> tuple[Uc, int, int]:
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
        for arch in archs:
            importlib.import_module(f"sem.arch.{arch}")
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
    def next_round(self):
        """Set the next random number as the new seed. Use when done with a
        single round of emulation (i.e. emulated every sample once)."""
        pass


class VarAttr(Flag):
    REGISTER = auto()
    MEMORY = auto()
    FUNCTION_ARG = auto()
    PTR = auto()


class Variable(ABC):
    def __init__(self, context: EmulationContext, attr: VarAttr) -> None:
        super().__init__()
        self._context: EmulationContext = context
        self._attr = attr

    @abstractmethod
    def set(data: bytes, emulator: Uc) -> bool:
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
        return emulator.reg_read(self._context.register_consts[self._reg]).to_bytes(
            self.size, "big"
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
            self._addr = int.from_bytes(self._addr_src.get(emulator), "big")
            emulator.mem_write(self._addr, data)
        except UcError:
            return False

    def get(self, emulator: Uc):
        return emulator.mem_read(self._addr, self._size)

    @property
    def name(self):
        return f"[{self._addr_src.name}] ({self.size})"

    @property
    def size(self):
        return self._size


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
            if variable.attr & VarAttr.PTR:
                # TODO: try to prevent overlapping
                data = self._random.randrange(*context.ptr_range, 0x10)
                data = data.to_bytes(variable.size, "big")
            else:
                data = self._random.randbytes(variable.size)
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

    def next_round(self):
        self.seed = self.get()
