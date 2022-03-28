import argparse
import io
import logging
from logging import debug, info, warning, error
from typing import Dict
from pathlib import Path

from ObjDef import UnlinkFile, ObjectDefinition
from make_obj import ElfFile, ElfProgBits, ElfSymbolType, ElfSymbolBind, ElfNoBits, ElfDataSection, ArmAttributesSection
from Buf import ByteBuffer
from Relocator import Relocator, default_symbol_name


def main():
    parser = argparse.ArgumentParser(description="Unlink a binary")
    parser.add_argument("-v", "--verbose", action="store_const", const=True, default=False,
                        dest="verbose", help="More logging output")
    parser.add_argument("-f", "--definition-file", required=True, type=argparse.FileType("r"), metavar="FILE",
                        dest="def_file", help="the file defining what objects to process")
    parser.add_argument("-i", "--input", type=argparse.FileType("rb"), metavar="FILE", action="append",
                        dest="in_files", help="input file required by definitions (may be specified multiple times)")
    parser.add_argument("-o", "--output-dir", required=True, type=Path, metavar="DIR", default=".",
                        dest="output_dir", help="destination directory for generated objects")
    # parser.print_help()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    log_format = "[%(levelname)s]: %(message)s"
    logging.basicConfig(level=log_level, format=log_format)

    outdir: Path = args.output_dir
    if not outdir.exists():
        outdir.mkdir(parents=True)

    sources: Dict[io.BufferedReader] = {n.name.split("/")[-1]: n for n in args.in_files}

    defs = UnlinkFile(args.def_file.read())

    failed = False
    for name, sf in defs.sources.items():
        if sf.name in sources:
            sf.data = sources[sf.name].read()
        else:
            error(f"Missing source file: {sf.name}")
            failed = True
    if failed:
        exit(1)

    info(f"Loaded definitions for {len(defs.objects)} object file(s).")
    for obj in defs.objects:
        debug(f"Starting to process object {obj.dest_file}")

        rel = Relocator()
        elf = ElfFile()
        prog_buf = ByteBuffer()

        file_base = defs.sources[obj.sections[0].file].base + obj.sections[0].start

        for section in obj.sections:
            section: ObjectDefinition.Section
            sources[section.file].seek(section.start)
            section_buf = ByteBuffer(sources[section.file].read(section.end - section.start))
            # file_base = defs.sources[section.file].base

            if section.section_type == ObjectDefinition.SectionType.TEXT_SECTION:
                if obj.mode == "arm":
                    rel.relocate_arm_section(elf, section_buf, file_base + section.start)
                elif obj.mode == "thumb":
                    rel.relocate_thumb_section(elf, section_buf, file_base + section.start)
                else:
                    raise ValueError(f"obj.mode is invalid: expected thumb or arm, got {obj.mode:r}")

            prog_buf.write(section_buf.getvalue())

        elf.add_section(ElfProgBits(prog_buf.getvalue(), file_base), ".text")
        elf.add_section(ElfDataSection(bytes(), 0), ".data")
        elf.add_section(ElfNoBits(0, 0), ".bss")
        elf.add_section(ArmAttributesSection(), ".ARM.attributes")

        # elf.add_symbol(".text", 0, 0, ElfSymbolType.STT_SECTION, ElfSymbolBind.STB_LOCAL, elf.section_index(".text"))
        # elf.add_symbol(".data", 0, 0, ElfSymbolType.STT_SECTION, ElfSymbolBind.STB_LOCAL, elf.section_index(".data"))
        # elf.add_symbol(".bss", 0, 0, ElfSymbolType.STT_SECTION, ElfSymbolBind.STB_LOCAL, elf.section_index(".bss"))
        # elf.add_symbol(".ARM.attributes", 0, 0, ElfSymbolType.STT_SECTION, ElfSymbolBind.STB_LOCAL, elf.section_index(".ARM.attributes"))

        for section in obj.sections:
            #print(section)
            if section.section_type == ObjectDefinition.SectionType.TEXT_SECTION:
                if obj.mode == "arm":
                    elf.add_symbol("$a", section.start, 0, ElfSymbolType.STT_NOTYPE, ElfSymbolBind.STB_LOCAL, elf.section_index(".text"))
                elif obj.mode == "thumb":
                    elf.add_symbol("$t", section.start, 0, ElfSymbolType.STT_NOTYPE, ElfSymbolBind.STB_LOCAL, elf.section_index(".text"))
            elif section.section_type == ObjectDefinition.SectionType.LITERAL_POOL_SECTION:
                # elf.add_symbol("$d", section.start, 0, ElfSymbolType.STT_NOTYPE, ElfSymbolBind.STB_LOCAL, elf.section_index(".text"))
                pass

        func_name = obj.func_name if obj.func_name else default_symbol_name(file_base)
        elf.add_symbol(func_name, 0, elf.get_section(".text").size(), ElfSymbolType.STT_FUNC, ElfSymbolBind.STB_GLOBAL, elf.section_index(".text"))

        with open(Path(outdir, obj.dest_file), "wb") as f:
            f.write(elf.to_bytes())

        debug(f"Finished object {obj.dest_file}")

    info(f"Generated {len(defs.objects)} objects.")


if __name__ == "__main__":
    main()
