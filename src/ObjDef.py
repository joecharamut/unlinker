from collections import namedtuple
import enum
from typing import Optional, List, Any, Dict


class ObjectDefinition:
    class SectionType(enum.Enum):
        TEXT_SECTION = enum.auto()
        LITERAL_POOL_SECTION = enum.auto()

    Section = namedtuple("Section", "section_type file start end")

    def __init__(self):
        self.mode = None
        self.dest_file = None
        self.func_name = None
        self.sections = []

    def __repr__(self):
        return f"<ObjectDefinition mode={self.mode!r} file={self.dest_file!r} function={self.func_name!r} sections={self.sections!r}>"


class SourceFile:
    def __init__(self, opts):
        self.name = opts[0]
        self.data = None

        self.base = 0

        for opt in opts:
            try:
                k, v = opt.split("=")
            except ValueError:
                continue
            if k == "base":
                self.base = int(v, 16 if v.startswith("0x") else 10)

    def __repr__(self):
        return f"<SourceFile name={self.name!r} has_data={self.data is not None}>"


class UnlinkFile:
    sources: Dict[str, SourceFile]
    objects: list[ObjectDefinition]

    def __init__(self, contents: str):
        self._text = contents
        self.sources = {}
        self.objects = []

        self.parse()

    def parse(self):
        nodes = []
        current_node: Optional[ObjectDefinition] = None

        for line in self._text.splitlines():
            line = line.split("#")[0].strip()
            if not line: continue  # handle commented out and blank lines

            keyword = line.split(" ")[0]
            args = line[len(keyword) + 1:]

            if keyword == "@sourcefile":
                if current_node:
                    raise SyntaxError("Error: @sourcefile definitions must be at top level")
                params = args.split(",")
                self.sources[params[0]] = SourceFile(params)
                continue
            elif keyword == "@obj":
                if current_node:
                    raise SyntaxError("Error: @obj definition must be at top level")
                current_node = ObjectDefinition()
                current_node.dest_file = args
                continue
            elif keyword == "@func":
                if not current_node or not isinstance(current_node, ObjectDefinition):
                    raise SyntaxError("Error: @func must be inside an object definition")
                current_node.func_name = args if len(args) > 0 else None
                continue
            elif keyword == "@mode":
                if not current_node or not isinstance(current_node, ObjectDefinition):
                    raise SyntaxError("Error: @mode must be inside an object definition")
                current_node.mode = args
                continue
            elif keyword == "@text":
                if not current_node or not isinstance(current_node, ObjectDefinition):
                    raise SyntaxError("Error: @text must be inside an object definition")
                file, start, end = args.split(":")
                start = int(start, 16 if start.startswith("0x") else 10)
                end = int(end, 16 if end.startswith("0x") else 10)
                current_node.sections.append(ObjectDefinition.Section(ObjectDefinition.SectionType.TEXT_SECTION, file, start, end))
                continue
            elif keyword == "@lpool":
                if not current_node or not isinstance(current_node, ObjectDefinition):
                    raise SyntaxError("Error: @lpool must be inside an object definition")
                file, start, end = args.split(":")
                start = int(start, 16 if start.startswith("0x") else 10)
                end = int(end, 16 if end.startswith("0x") else 10)
                current_node.sections.append(ObjectDefinition.Section(ObjectDefinition.SectionType.LITERAL_POOL_SECTION, file, start, end))
                continue
            elif keyword == "@endfunc":
                if not current_node or not isinstance(current_node, ObjectDefinition):
                    raise SyntaxError("Error: @endfunc must be inside an object definition")
                continue
            elif keyword == "@endobj":
                if not current_node:
                    raise SyntaxError("Error: Cannot end a non-existant node")
                self.objects.append(current_node)
                current_node = None
            else:
                print(f"unknown keyword: {line}")

    def __repr__(self) -> str:
        return f"<UnlinkFile sources={self.sources!r} objects={self.objects!r}>"
