import re
import os
import sys
import importlib

from ghidra.program.model.data import CategoryPath, \
    EnumDataType, \
    StructureDataType, \
    TypedefDataType, \
    ArrayDataType, \
    DataTypeConflictHandler
from ghidra.program.model.data import UnsignedIntegerDataType, \
    IntegerDataType, ShortDataType, UnsignedShortDataType, \
    CharDataType, UnsignedCharDataType
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressFactory


def enum_length(data):
    bs = 0
    for d in data:
        bs = max(d[1].bit_length(), bs)
    el = 1 if bs % 8 > 0 else 0
    return max(int(bs/8) + el, 1)


class StmImporter:
    def __init__(self, filename):
        if not os.path.exists(filename):
            print("Unable to import {} as it does not appear to exist?".format(filename))
            return
        if os.path.isdir(filename):
            print("Unable to import {} as it is a directory".format(filename))
            return

        sys.path.append(os.path.dirname(filename))
        mod_name, _ = os.path.splitext(os.path.basename(filename))
        self.data = importlib.import_module(mod_name)
        self.dtm = currentProgram.getDataTypeManager()
        self.symbol_table = currentProgram.getSymbolTable()
        self.address_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
        self.listing = currentProgram.getListing()

    def import_all(self):
        self.add_categories()
        self.add_enums()
        self.ensure_standard_types()
        self.add_typedefs()
        self.add_structures()
        self.add_labels()

    def get_data_type(self, cat, fld_type, base_type=False):
        data_type_re = re.compile("(?P<type>[a-zA-Z_0-9]+)\s*(?P<pointer>\*)?\s*(?P<array>\[[0-9]+\])?")
        data_type = None
        opts = data_type_re.match(fld_type)
        if opts is None:
            print("Error extracing type information from {}".format(fld_type))
            return None
        matches = []
        self.dtm.findDataTypes(opts.group('type'), matches)
        try:
            data_type = matches[0]
        except IndexError:
            if opts.group('type') in self.data.Structures:
                self.add_structure(cat+":"+opts.group('type'))
                return self.get_data_type(cat, fld_type)
            print("Unable to find a data type for {}".format(opts.group('type')))
            return None

        if base_type:
            return data_type
        
        if opts.group('pointer') is not None:
            data_type = self.dtm.getPointer(data_type)

        if opts.group('array') is not None:
            len = int(opts.group('array')[1:-1])
            array_data_type = ArrayDataType(data_type, len, data_type.length)
            if cat != "":
                array_data_type.setCategoryPath(CategoryPath(cat))
            data_type = self.dtm.addDataType(array_data_type,DataTypeConflictHandler.DEFAULT_HANDLER)

        return data_type

    def ensure_standard_types(self):
        width = currentProgram.getDefaultPointerSize()
        cat = CategoryPath("/")

        std_types = {
            'uint32_t': [4, 'Unsigned'],
            'int32_t': [4, ''],
            'uint16_t': [2, 'Unsigned'],
            'int16_t': [2, ''],
            'uint8_t': [1, 'Unsigned'],
            'int8_t': [1, ''],
        }
        
        for typ, opts in std_types.items():
            ck = self.get_data_type("", typ)
            if ck is None:
                obj = None
                if width == opts[0]:
                    obj = globals().get(opts[1]+"IntegerDataType")
                elif width == opts[0] * 2:
                    obj = globals().get(opts[1]+"ShortDataType")
                elif opts[0] == 1:
                    obj = globals().get(opts[1]+"CharDataType")
                if obj is None:
                    print("Unable to add standard type {} as no matching type was found".format(typ))
                    continue
                td = TypedefDataType(cat, typ, obj())
                self.dtm.addDataType(td, DataTypeConflictHandler.REPLACE_HANDLER)

    def add_categories(self):
        if not hasattr(self.data, "Categories"):
            return
        for cat in self.data.Categories:
            self.dtm.createCategory(CategoryPath(cat))

    def add_enums(self):
        if not hasattr(self.data, "Enums"):
            return
        for title, data in self.data.Enums.items():
            cat, name = title.split(':')

            enum = EnumDataType(name, enum_length(data))
            for d in data:
                enum.add(d[0], d[1], d[2])
            enum.setCategoryPath(CategoryPath(cat))
            self.dtm.addDataType(enum, DataTypeConflictHandler.DEFAULT_HANDLER)

    def add_typedefs(self):
        if not hasattr(self.data, "Typedefs"):
            return

        for title, tdefcomm in self.data.Typedefs.items():
            cat, name = title.split(':')
            tdef, comment = tdefcomm.split(':')

            dt = self.get_data_type(cat, name)
            if dt is None:
                print("WARNING: Unable to add typedef {} as failed to find data type {}".format(tdef, name))
                continue

            td = TypedefDataType(CategoryPath(cat), tdef, dt)
            self.dtm.addDataType(td, DataTypeConflictHandler.DEFAULT_HANDLER)

    def add_structure(self, structure_name):
        cat, name = structure_name.split(":")

        pack = False
        st = StructureDataType(name, 0)
        for f in self.data.Structures[structure_name]:        
            dt = self.get_data_type(cat, f[0])
            if dt is None:
                print("WARNING: Unable to add field {}:{} due no matching data type for {}".format(name, f[1], f[0]))
                continue

            if ':' in f[0]:
                st.addBitField(dt, dt.length, f[1], f[2])
                pack = True
            else:
                st.add(dt, dt.length, f[1], f[2])

        st.setCategoryPath(CategoryPath(cat))
        if pack:
            st.setPackingEnabled(True)
        self.dtm.addDataType(st, DataTypeConflictHandler.DEFAULT_HANDLER)

    def add_structures(self):
        if not hasattr(self.data, "Structures"):
            return
        for s_name in sorted(self.data.Structures.keys()):
            self.add_structure(s_name)

    def add_labels(self):
        if not hasattr(self.data, "Labels"):
            return
        
        namespace = self.symbol_table.getNamespace("Peripherals", None)
        if not namespace:
            namespace = self.symbol_table.createNameSpace(None, "Peripherals", SourceType.ANALYSIS)

        for lbl in sorted(self.data.Labels.keys()):
            data = self.data.Labels[lbl]

            addr = self.address_space.getAddress(data[1])
            self.symbol_table.createLabel(addr, lbl, namespace, SourceType.USER_DEFINED)

            dt = self.get_data_type("", data[0], base_type=True)

            try:
                self.listing.createData(addr, dt, False)
            except ghidra.program.model.util.CodeUnitInsertionException:
                pass

            try:
                mem = currentProgram.memory.createUninitializedBlock(lbl, addr, dt.length, False)
                mem.setRead(True)
                mem.setWrite(True)
                mem.setExecute(False)
                mem.setVolatile(True)
                mem.setComment("Added by STM importer script for "+lbl)
            except ghidra.program.model.mem.MemoryConflictException:
                pass

file_to_import = askFile("Choose STM definition file", "Load STM Definitions File")
importer = StmImporter(str(file_to_import))
importer.import_all()
