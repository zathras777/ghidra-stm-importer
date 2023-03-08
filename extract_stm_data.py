import sys
import os
import re

START_RE = re.compile("[enum|struct|typedef|#define]")
END_RE = re.compile(".*\}.*;")
ENUM_RE = re.compile(".*([a-zA-Z0-9_]+).*=.*([0-9hx]+).*,(.*?)")
NUM_RE = re.compile("^(0x([0-9A-Fa-f]+)|[\-0-9]+)U?L?")
CAST_RE = re.compile("\(\(([A-Za-z0-9_ \*]+)\)\s*(\(?[A-Za-z0-9_+ \<]+\)?)\s*?\)")
DEFINE_RE = re.compile(r'\#define\s+(?P<name>[_A-Za-z0-9]+)\s*(?P<value>[\(\)A-Za-z0-9 _+\<\*]+)\s*?(?P<comment>.*)?')        


def tidy_comment(comm:str) -> str:
    return comm.replace("/*!<", "").replace("*/", "").replace("/*", "").strip()


def str_to_int(txt:str) -> int:
    txt = txt.replace("U", "").replace("L", "").strip()
    if '0x' in txt:
        txt = txt.replace("U", "").replace("L", "")
        return int(txt, 16)
    return int(txt)


def get_value(val:str):
    val = val.replace(",", "").strip()
    if val == "":
        return -1
    num = NUM_RE.match(val)
    if num is None:
        return val
    if '0x' in val:
        return int(num.group(1), 16)
    try:
        return int(num.group(1))
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
        self.labels:dict = {}

    def create_data(self):
        self.update_enums()
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
        data += "}\nLabels = {\n"
        for l, d in self.labels.items():
            data += f"    {quote(l)}: {d},\n"
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
            if entry == "{" or entry.startswith("/*"):
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

    def txt_to_int(self, val_txt:str):
        if len(val_txt) == 0:
            return None
        if val_txt in ['+', '<<', '>>']:
            return val_txt
        elif NUM_RE.match(val_txt) is None:
            if val_txt not in self.constants:
                print(f"Missing constant: {val_txt}")
                return None
            return self.constants[val_txt]
        return str_to_int(val_txt)

    def get_value(self, val_txt:str) -> int:
        val_txt = val_txt.strip().replace("(", "").replace(")", "")
        parts = val_txt.split(' ')
        if len(parts) == 1:
            return self.txt_to_int(val_txt)

        vals = [self.txt_to_int(p.strip()) for p in parts]
        if vals[1] == "+":
            return vals[0] + vals[2]
        elif vals[1] == "<<":
            return vals[0] << vals[2]
        return vals[0]
        
    def add_define(self, category:str, txt:list[str]):
        if '()' in txt[0] or txt[0].startswith("#if") or txt[0].startswith("#elif"):
            return

        ck = DEFINE_RE.match(txt[0])
        if ck is None:
            print("Failed to parse " + txt[0])
            return
        if ck.group('name').startswith("IS_"):
            return

        if "((" in ck.group('value'):
            var = CAST_RE.match(ck.group('value'))
            if var is not None:
                self.labels[ck.group('name')] = [var.group(1), self.get_value(var.group(2))]
            return
        
        val = self.get_value(ck.group('value'))
        if val is None and ck.group('value') in self.labels:
            self.labels[ck.group('name')] = self.labels[ck.group('value')]

        self.constants[ck.group('name')] = val

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
