from abc import ABC, abstractmethod
from enum import Flag, auto
import os
from sem.emulation import Program, VarAttr
import re


class NativeVarAttr(Flag):
    INT = auto()
    UINT = auto()
    PTR = auto()


class NativeContext():
    def __init__(self) -> None:
        super().__init__()
        self._variables: list[NativeVariable] = []
        self._result_variables: list[NativeVariable] = []

    def run_program(self, program: Program) -> None:
        raise NotImplementedError()

    def set_fn(self, program: Program) -> None:
        pattern = re.compile(r'^(?P<ret_ty>int32_t)\s+' + program.fn_name +
                             r'\((?P<arg_list>[^)]+)\)')
        c_file_path = os.path.join(program.data_dir, "csmith.c")
        with open(c_file_path, "r") as c_file:
            c_source_lines = [line.rstrip() for line in c_file.readlines()]

        for line in c_source_lines:
            m = re.fullmatch(pattern, line)
            if not m:
                continue
            self._result_variables = self._parse_arg_tys(m.group("ret_ty"))[0]
            self._variables = self._parse_arg_tys(m.group("arg_list"))

    def _parse_arg_tys(self, arg_list: str) -> list["NativeVariable"]:
        if not arg_list:
            return []
        args: list[str] = [ty.strip() for ty in arg_list.split(sep=",")]
        native_vars: list[NativeVariable] = []
        for arg in args:
            arg_split = arg.split()

            ty = arg_split[0]
            is_pointer = False
            # pointer type
            if len(arg_split) == 3:
                is_pointer = True

            match = re.search(r'([a-zA-Z]+)(\d+)_t', ty)
            if match:
                ty_attr = match.group(1)
                ty_size = int(match.group(2))
            if ty_attr == "int":
                native_var_attr = NativeVarAttr.INT
            elif ty_attr == "uint":
                native_var_attr = NativeVarAttr.UINT
            if is_pointer:
                native_var_attr = NativeVarAttr.PTR

            native_var_size = int(ty_size)
            native_vars.append(NativeVariable(
                native_var_attr, native_var_size, self))
        return native_vars

    @staticmethod
    def get() -> "NativeContext":
        return NativeContext()


class NativeVariable():
    def __init__(self,
                 attr: NativeVarAttr,
                 size: int,
                 context: NativeContext) -> None:
        super().__init__()
        self._context: NativeContext = context
        self._attr = attr
        self._size = size
        self._value = None

    def set(data: bytes) -> bool:
        pass

    def get(self) -> bytes:
        pass

    def name(self):
        pass

    @property
    def attr(self) -> VarAttr:
        return self._attr

    @attr.setter
    def attr(self, new_attr: VarAttr):
        self._attr = new_attr
