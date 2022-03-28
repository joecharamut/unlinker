import struct
import io
import subprocess
from enum import IntEnum, IntFlag
from typing import Optional, Any
import abc
from logging import debug

import capstone

from Buf import ByteBuffer


print = debug


class ElfSectionType(IntEnum):
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_SHLIB = 10
    SHT_DYNSYM = 11

    SHT_ARM_ATTRIBUTES = 0x70000003


class ElfSectionFlag(IntFlag):
    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    SHF_MASKPROC = 0xf0000000


class ElfSymbolBind(IntEnum):
    STB_LOCAL = 0 << 4
    STB_GLOBAL = 1 << 4
    STB_WEAK = 2 << 4
    STB_LOPROC = 14 << 4
    STB_HIPROC = 15 << 4


class ElfSymbolType(IntEnum):
    STT_NOTYPE = 0
    STT_OBJECT = 1
    STT_FUNC = 2
    STT_SECTION = 3
    STT_FILE = 4
    STT_LOPROC = 13
    STT_HIPROC = 15


class ArmFlags(IntEnum):
    EF_ARM_ABI = 0x05000000


class ArmRelocationCode(IntEnum):
    R_ARM_NONE = 0
    R_ARM_THM_CALL = 10
    R_ARM_CALL = 28


class ElfSection(abc.ABC):
    def __init__(self) -> None:
        self.type = 0
        self.flags = 0
        self.addr = 0
        self.link = 0
        self.info = 0
        self.align = 1
        self.entsize = 0

    def get_header_bytes(self, name_offset: int, file_offset: int) -> bytes:
        buf = ByteBuffer()
        buf.write_u32(name_offset)
        buf.write_u32(self.type)
        buf.write_u32(self.flags)
        buf.write_u32(self.addr)
        buf.write_u32(file_offset)
        buf.write_u32(self.size())
        buf.write_u32(self.link)
        buf.write_u32(self.info)
        buf.write_u32(self.align)
        buf.write_u32(self.entsize)
        return buf.getvalue()

    @abc.abstractmethod
    def size(self) -> int:
        raise AssertionError

    @abc.abstractmethod
    def to_bytes(self, **kwargs) -> bytes:
        raise AssertionError


class ElfProgBits(ElfSection):
    def __init__(self, bits: bytes, vaddr=0):
        super().__init__()
        self.type = ElfSectionType.SHT_PROGBITS
        self.flags = ElfSectionFlag.SHF_ALLOC | ElfSectionFlag.SHF_EXECINSTR
        self.addr = vaddr
        self.align = 4

        if not isinstance(bits, bytes):
            raise TypeError(f"{type(bits)} is not bytes")
        self.bits = bits

    def size(self):
        return len(self.bits)

    def to_bytes(self, **kwargs):
        return self.bits


class ElfDataSection(ElfSection):
    def __init__(self, bits: bytes, vaddr=0):
        super().__init__()
        self.type = ElfSectionType.SHT_PROGBITS
        self.flags = ElfSectionFlag.SHF_ALLOC | ElfSectionFlag.SHF_WRITE
        self.addr = vaddr

        if not isinstance(bits, bytes):
            raise TypeError(f"{type(bits)} is not bytes")
        self.bits = bits

    def size(self):
        return len(self.bits)

    def to_bytes(self, **kwargs):
        return self.bits


class ElfNoBits(ElfSection):
    def __init__(self, vaddr=0, size=0):
        super().__init__()
        self.type = ElfSectionType.SHT_NOBITS
        self.flags = ElfSectionFlag.SHF_ALLOC | ElfSectionFlag.SHF_WRITE
        self.addr = vaddr
        self._size = size

    def size(self):
        return self._size

    def to_bytes(self, **kwargs):
        return bytes()


class ElfStringTable(ElfSection):
    def __init__(self):
        super().__init__()
        self.type = ElfSectionType.SHT_STRTAB
        self._strings = []

    def insert(self, string) -> int:
        if string not in self._strings:
            self._strings.append(string)
        return self.offsetof(string)

    def offsetof(self, string):
        offset = 1  # skip first null byte
        for s in self._strings:
            if s == string:
                break
            offset += len(s) + 1
        else:
            raise KeyError
        return offset

    def __contains__(self, item):
        return self._strings.__contains__(item)

    def size(self):
        size = 1
        for s in self._strings:
            size += len(s) + 1
        return size

    def to_bytes(self, **kwargs) -> bytes:
        buf = ByteBuffer()

        buf.write(b"\0")
        for s in self._strings:
            buf.write_asciiz(s)

        return buf.getvalue()


class ElfSymbolTable(ElfSection):
    def __init__(self):
        super().__init__()
        self.type = ElfSectionType.SHT_SYMTAB
        self.align = 4
        self.info = 0
        self.entsize = 0x10
        self._entries = []

    def add_symbol(self, name, value, size, sym_type, binding, index=0):
        self._entries.append((name, value, size, sym_type, binding, index))

    def index_of(self, name):
        for i, ent in enumerate(self._entries):
            if ent[0] == name:
                return i + 1
        raise KeyError

    def size(self):
        return (len(self._entries) + 1) * 0x10

    def to_bytes(self, string_table: ElfStringTable = None, **kwargs):
        buf = ByteBuffer()

        local_syms = 1
        for name, value, size, sym_type, binding, index in self._entries:
            if binding == ElfSymbolBind.STB_LOCAL:
                local_syms += 1

        self.info = local_syms

        buf.write(b"\0" * self.entsize)  # null entry
        for i, (name, value, size, sym_type, binding, index) in enumerate(self._entries):
            buf.write_u32(string_table.insert(name))
            buf.write_u32(value)
            buf.write_u32(size)
            buf.write_u8(sym_type | binding)
            buf.write_u8(0)
            buf.write_u16(index)

        return buf.getvalue()


class ElfRelSection(ElfSection):
    def __init__(self):
        super().__init__()
        self.type = ElfSectionType.SHT_REL
        self.entsize = 0x08
        self._entries = []

    def add_relocation(self, offset, symbol_idx, rel_type):
        self._entries.append((offset, (symbol_idx << 8) + rel_type))

    def size(self) -> int:
        return len(self._entries) * self.entsize

    def to_bytes(self, **kwargs) -> bytes:
        buf = ByteBuffer()

        for i, (offset, info) in enumerate(self._entries):
            buf.write_u32(offset)
            buf.write_u32(info)

        return buf.getvalue()


class ArmAttributesSection(ElfSection):
    def __init__(self):
        super().__init__()
        self.type = ElfSectionType.SHT_ARM_ATTRIBUTES

        self.default_attrs = bytes.fromhex("412f 0000 0061 6561 6269 0001 2500 0000 0536 4b00 0609 0801 0901 0a02 1204 1401 1501 1703 1801 1901 1a01 1c01 1e06 2201")

    def size(self):
        return len(self.default_attrs)

    def to_bytes(self, **kwargs):
        return self.default_attrs


class SectionTable:
    def __init__(self):
        self._L = []

    def insert(self, name, section):
        for k, v in self._L:
            if name == k:
                raise KeyError(f"Section {name} already exists")
        self._L.append((name, section))

    def index_of(self, name):
        for i, (k, v) in enumerate(self._L):
            if name == k:
                return i + 1
        raise KeyError(f"Key {name} not found")

    def get(self, name):
        for i, (k, v) in enumerate(self._L):
            if name == k:
                return v
        raise KeyError(f"Key {name} not found")

    def num_sections(self):
        return len(self._L) + 1  # sections + null entry

    def __iter__(self):
        self._i = 0
        return self

    def __next__(self) -> ElfSection:
        i = self._i
        self._i += 1
        if i < len(self._L):
            return self._L[i]
        raise StopIteration


class ElfRelArmCall:
    def __init__(self, opcode, target):
        self.opcode = opcode
        self.target = target

    def resolve_target(self) -> Optional[str]:
        return "nnInitRegion"


class SymbolServer:
    def __init__(self):
        pass

    def symbol_at(self, addr) -> Optional[str]:
        if addr == "#0x100024":
            return "nnInitRegion"
        return None


def get_rel_type(instr_bytes: bytes, offset: int, thumb: bool = False) -> Optional[ElfRelArmCall]:
    # todo: handle thumb mode
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB if thumb else capstone.CS_MODE_ARM)
    disassembly = md.disasm_lite(instr_bytes, offset)
    tup = (address, size, mnemonic, op_str) = next(disassembly)
    print(tup)

    if mnemonic == "bl" or mnemonic == "blx":
        instr_val, = struct.unpack("<I", instr_bytes)
        result = struct.pack("<I", instr_val & 0x03FFFFFE)
        opcode = struct.pack("<I", (instr_val & 0xFF000000) + 0xfffffe)
        print(f"R_ARM_CALL[op={opcode}, sym={result}]")
        return ElfRelArmCall(opcode, op_str)

    return None


class ElfFile:
    def __init__(self):
        self._sections = SectionTable()

        self._strings = ElfStringTable()
        self._sh_strings = ElfStringTable()
        self._syms = ElfSymbolTable()

        self._rels = None

    def add_section(self, section: ElfSection, name: str):
        self._sections.insert(name, section)
        self._sh_strings.insert(name)

    def section_index(self, name: str):
        return self._sections.index_of(name)

    def get_section(self, name: str):
        return self._sections.get(name)

    def add_symbol(self, name, value, size, sym_type, binding, index=0):
        print(f"adding symbol: {name}:{value}")
        self._syms.add_symbol(name, value, size, sym_type, binding, index)

    def add_relocation(self, offset, symbol, rel_type):
        if self._rels is None:
            self._rels = ElfRelSection()
            self.add_section(self._rels, ".rel.text")

        self._syms.add_symbol(symbol, 0, 0, ElfSymbolType.STT_FUNC, ElfSymbolBind.STB_GLOBAL)
        self._rels.add_relocation(offset, self._syms.index_of(symbol), rel_type)

    def to_bytes(self) -> bytes:
        # add these last
        self.add_section(self._syms, ".symtab")
        self.add_section(self._strings, ".strtab")
        self.add_section(self._sh_strings, ".shstrtab")

        self._syms.link = self.section_index(".strtab")

        buf = ByteBuffer()

        # e_ident
        buf.write(b"\x7fELF")  # magic
        buf.write_u8(0x01)     # 32 bit
        buf.write_u8(0x01)     # little endian
        buf.write_u8(0x01)     # elf version 1
        buf.write_u8(0x00)     # sysv abi
        buf.write_u8(0x00)     # abi version
        buf.write(b"\0" * 7)   # padding

        # rest of elf header
        buf.write_u16(0x01)  # relocatable elf file
        buf.write_u16(0x28)  # arm machine
        buf.write_u32(0x01)  # elf version 1
        buf.write_u32(0x00)  # no entrypoint for object file
        buf.write_u32(0x00)  # no phdrs for object file
        sht_index_offset = buf.tell(); buf.write_u32(0x00)  # section header table offset
        buf.write_u32(0x5000000)  # flags
        buf.write_u16(0x34)  # header size
        buf.write_u16(0x00)  # program header table entry size (optional for obj)
        buf.write_u16(0x00)  # program header table entries (optional for obj)
        buf.write_u16(0x28)  # section header table entry size
        buf.write_u16(self._sections.num_sections())  # section header table entries
        buf.write_u16(self._sections.index_of(".shstrtab"))  # section header string table index

        # sht_offset = buf.tell()
        # buf.write(b"\0"*0x28 * self._sections.num_sections())  # reserve space for section headers

        section_headers = []

        for i, (name, section) in enumerate(self._sections):
            name: str
            section: ElfSection

            print(f"writing section {i+1} \"{name}\"")
            section_offset = buf.end()
            buf.write(section.to_bytes(string_table=self._strings))

            # if isinstance(section, ElfSymbolTable):
            #     section.link = self._sections.index_of(".strtab")
            #
            # if isinstance(section, ElfRelSection):
            #     section.link = self._sections.index_of(".symtab")
            #     section.info = self._sections.index_of(".text")

            section_headers.append((name, section, section_offset))

        sht_offset = buf.end()
        buf.write(b"\0"*0x28)  # null entry
        for i, (name, section, section_offset) in enumerate(section_headers):
            buf.write(section.get_header_bytes(self._sh_strings.offsetof(name), section_offset))

        buf.write_u32(sht_offset, at=sht_index_offset)



        return buf.getvalue()
