import sys
import os
import re

START_RE = re.compile("[enum|struct|typedef|#define]")
END_RE = re.compile(".*\}.*;")
ENUM_RE = re.compile(".*([a-zA-Z0-9_]+).*=.*([0-9hx]+).*,(.*?)")
NUM_RE = re.compile("(0x)?([0-9A-Fa-f]+)U?L?")


def tidy_comment(comm:str) -> str:
    return comm.replace("/*!<", "").replace("*/", "").replace("/*", "").strip()


def get_value(val:str):
    val = val.replace(",", "").strip()
    if val == "":
        return -1
    num = NUM_RE.search(val)
    if num is None:
        return val
    if num.group(1) is not None:
        return int(num.group(2), 16)
    try:
        return int(num.group(2))
    except ValueError:
        return val


class Enum:
    def __init__(self, category:str, name:str):
        self.category = category
        self.name = name
        self.entries = []

    def add(self, ent:str, val:str, comment:str):
        ent = ent.replace(",", "").strip()
        val = get_value(val)
        if val == -1:
            val = self.entries[-1][1] + 1
        self.entries.append([ent, val, tidy_comment(comment)])

    def values(self) -> str:
        rv = []
        for k,v in self.entries.items():
            rv.append({k: v})


class Structure:
    def __init__(self, cat:str, name:str):
        self.category = cat
        self.name = name
        self.fields = []

    def add(self, outputs:list[str]):
        outputs[2] = tidy_comment(outputs[2])
        if ':' in outputs[1]:
            idx = outputs[1].find(':')
            outputs[0] += outputs[1][idx:-1]
            outputs[1] = outputs[1][:idx]
        if '[' in outputs[1]:
            idx = outputs[1].find('[')
            outputs[0] += outputs[1][idx:-1]
            outputs[1] = outputs[1][:idx]
        if outputs[1].endswith(';'):
            outputs[1] = outputs[1][:-1]
        if len(outputs[1]) == 0:
            outputs[1] = 'reserved'
        if outputs[1].startswith("*"):
            outputs[0] += " *"
            outputs[1] = outputs[1][1:]
        self.fields.append([outputs[0], outputs[1], tidy_comment(outputs[2])])


class ParsedTypes:
    def __init__(self):
        self.enums:list[Enum] = []
        self.structures:list[Structure] = []
        self.typedefs:dict = {}
        self.categories:list[str] = []
        self.constants:dict[str, int] = {}

    def create_data(self):
        def quote(x):
            return '"'+x+'"'
        data = "Categories = [\n"
        data += '\n'.join([f"    {quote(x)}," for x in self.categories])
        data += "\n]\nEnums = {\n"
        for e in self.enums:
            data += f"    {quote(e.category+':'+e.name)}: [\n"
            for ee in e.entries:
                data += f"        {ee},\n"
            data += "    ],\n"
        data += "}\nTypedefs = {\n"
        for t, v in self.typedefs.items():
            data += f"    {quote(t)}: {quote(v)},\n"
        data += "}\nStructures = {\n"
        for s in self.structures:
            data += f"    {quote(s.category+':'+s.name)}: [\n"
            for cc in s.fields:
                data += f"        {cc},\n"
            data += "    ],\n"
        data += "}\n"
        return data

    def update_enums(self):
        for e in self.enums:
            for ee in e.entries:
                if ee[1] in self.constants:
                    ee[1] = self.constants[ee[1]]
                elif isinstance(ee[1], str) and ee[1][0] == "!":
                    ee[1] = 1
                elif isinstance(ee[1], str):
                    print(f"Missing definition for {ee[1]}")

    def parse_file(self, fn:str):
        name = "/"+os.path.basename(fn)[:-2]
        with open(fn, "r", errors='ignore') as inc_file:
            txt:list[str] = []
            lines = inc_file.readlines()

            for l in lines:
                if START_RE.match(l):
                    if len(txt) > 0:
                        if "define" in txt[0]:
                            self.add_define(name, txt)
                    if l.startswith('typedef') and ';' in l:
                        self.add_typedef(name, l.strip())
                        txt = []
                    else:
                        txt = [l.strip()]
                    continue
                if len(txt):
                    txt.append(l.strip())
                if END_RE.match(l):
                    if len(txt) > 0:
                        if "enum" in txt[0]:
                            self.add_enum(name, txt)
                        elif "struct" in txt[0]:
                            self.add_structure(name, txt)
                        txt = []

    def add_enum(self, cat:str, txt:list[str]):
        if cat not in self.categories:
            self.categories.append(cat)
        enum = Enum(cat, txt[-1][1:-1].strip())

        for entry in txt[1:-1]:
            if entry == "{":
                continue
            while '  ' in entry:
                entry = entry.replace('  ', ' ')
            parts = entry.split()
            if len(parts) == 0:
                continue
            if "=" in parts[0]:
                name, val = parts[0].split("=")
                enum.add(name, val, " ".join(parts[1:]))
            elif len(parts) == 1:
                enum.add(parts[0], "", "")
            elif parts[1] == "=":
                enum.add(parts[0], parts[2], " ".join(parts[3:]))
            elif "=" in parts[1]:
                val = parts[1].replace("=", "").replace(",", "")
                enum.add(parts[0], val, " ".join(parts[2:]))
            elif len(parts) > 1:
                enum.add(parts[0], "", " ".join(parts[1:]))
        self.enums.append(enum)

    def add_structure(self, cat:str, txt:list[str]):
        if cat not in self.categories:
            self.categories.append(cat)
        st = Structure(cat, txt[-1][1:-1].strip())

        outputs = []
        for entry in txt[1:-1]:
            while '  ' in entry:
                entry = entry.replace('  ', ' ')
            parts = entry.split()
            if len(parts) < 3:
                continue
            if ';' not in parts[1] and ';' not in parts[2]:
                if len(outputs) > 2:
                    outputs[2] += " " + " ".join(parts)
            else:
                if len(outputs) == 3:
                    st.add(outputs)
                offset = 0
                if parts[0].startswith('__'):
                    #parts[1] = parts[0] + " " + parts[1]
                    offset = 1
                if ';' in parts[2+offset]:
                    outputs = [parts[0+offset], parts[1+offset] + parts[2+offset], " ".join(parts[3+offset:])]
                else:
                    outputs = [parts[0+offset], parts[1+offset]," ".join(parts[2+offset:])]
        if len(outputs) == 3:
            st.add(outputs)
        self.structures.append(st)

    def add_define(self, category:str, txt:list[str]):
        if '()' in txt[0] or txt[0].startswith("#if"):
            return
        while '  ' in txt[0]:
                txt[0] = txt[0].replace('  ', ' ')
        parts = txt[0].split()

        if len(parts) < 3 or "(" in parts[1] or parts[2][0] != "(" or parts[2][-1] != ")":
            return
        vals = parts[2].split(")")
        if len(vals) >= 3:
            self.constants[parts[1]] = get_value(vals[1])
        else:
            self.constants[parts[1]] = get_value(vals[0])

    def add_typedef(self, category:str, txt:str):
        while '  ' in txt:
            txt = txt.replace('  ', ' ')
        parts = txt.split(' ')
        end = 2
        for x in range(2, len(parts)):
            if ';' in parts[x]:
                end = x
        tdef = " ".join(parts[2:end+1])
        tdef = tdef.replace(';','')
        if end < len(parts):
            tdef += ":"+" ".join(parts[end+1:])
        self.typedefs[category + ":" + parts[1]] = tdef

    def parse_directory(self, dd:str="."):
        for f in os.listdir(dd):
            poss = os.path.join(dd, f)
            if os.path.isdir(poss):
                continue
            self.parse_file(os.path.join(dd, f))
        self.update_enums()

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} output_filename <file_or_directory> ...")
        return

    ofile = sys.argv[1]

    pt = ParsedTypes()
    for inc in sys.argv[2:]:
        if not os.path.exists(inc):
            print(f"Skipping {inc} as file/directory does not exist")
        if os.path.isdir(inc):
            pt.parse_directory(inc)
        else:
            pt.parse_file(inc)

    with open(ofile, "w") as fh:
        fh.write(pt.create_data())
    print(f"Created {ofile}")

if __name__ == '__main__':
    main()
