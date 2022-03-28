import enum
import struct

import capstone

from make_obj import ElfFile, ArmRelocationCode
from Buf import ByteBuffer


class RelocationMode(enum.IntFlag):
    USE_GENERIC_NAMES = enum.auto()
    SEARCH_NAMES = enum.auto()


def default_symbol_name(addr):
    return f"FUN_{addr:x}"


class Relocator:
    def __init__(self):
        self._arm_mach = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        self._arm_mach.detail = True
        self._thumb_mach = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        self._thumb_mach.detail = True

    def relocate_arm_section(self, elf: ElfFile, buf: ByteBuffer, base_addr: int):
        size = buf.end()
        buf.seek(0)
        if size % 4 != 0:
            raise ValueError(f"Buffer is not instruction-aligned (0x{base_addr:x}:0x{base_addr+size:x})")

        offset = 0
        for instr in self._arm_mach.disasm(buf.read(size), base_addr):
            instr: capstone.CsInsn
            #print(instr.mnemonic, instr.op_str)
            if instr.mnemonic in ["bl", "blx"] and instr.op_str[0] == "#":  # call immediate
                instr_bytes, = struct.unpack("<I", instr.bytes)
                op_value = int(instr.op_str[1:], 16)
                masked_instr = (instr_bytes & 0xff000000) + 0x00fffffe
                buf.write_u32(masked_instr, at=offset)
                elf.add_relocation(offset, default_symbol_name(op_value), ArmRelocationCode.R_ARM_CALL)
            offset += instr.size

    def relocate_thumb_section(self, elf: ElfFile, buf: ByteBuffer, base_addr: int):
        size = buf.end()
        buf.seek(0)
        if size % 2 != 0:
            raise ValueError("Buffer is not instruction-aligned")

        offset = 0
        for address, size, mnemonic, op_str in self._thumb_mach.disasm_lite(buf.read(size), base_addr):
            #print((address, size, mnemonic, op_str))
            if mnemonic in ["bl"]:
                instr = buf.read_u32(at=offset)
                op_value = int(op_str[1:], 16)
                masked_instr = (instr & 0xfe000001) + 0x00fffffe
                # todo: figure out where that f7 comes from
                # todo: thumb endianness?
                buf.write_u32(0xfffef7ff, at=offset)
                elf.add_relocation(offset, default_symbol_name(op_value), ArmRelocationCode.R_ARM_THM_CALL)
            offset += size

