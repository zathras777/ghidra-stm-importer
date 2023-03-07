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


def enum_length(data):
    bs = 0
    for d in data:
        bs = max(d[1].bit_length(), bs)
    el = 1 if bs % 8 > 0 else 0
    return max(int(bs/8) + el, 1)


class StmImporter:
    def __init__(self, filename):
        if not os.path.exists(filename):
            print("Unable to import %s as it does not appear to exist?".format(filename))
            return
        if os.path.isdir(filename):
            print("Unable to import %s as it is a directory".format(filename))
            return

        sys.path.append(os.path.dirname(filename))
        mod_name, _ = os.path.splitext(os.path.basename(filename))
        self.data = importlib.import_module(mod_name)
        self.dtm = currentProgram.getDataTypeManager()

    def import_all(self):
        self.add_categories()
        self.add_enums()
        self.add_typedefs()
        self.add_structures()

    def get_data_type(self, cat, fld_type):
        data_type_re = re.compile("(?P<type>[a-zA-Z_0-9]+)\s*(?P<pointer>\*)?\s*(?P<array>\[[0-9]+\])?")
        data_type = None
        opts = data_type_re.match(fld_type)
        if opts is None:
            print("Error extracing type information from %s".format(fld_type))
            return None
        matches = []
        self.dtm.findDataTypes(opts.group('type'), matches)
        try:
            data_type = matches[0]
        except IndexError:
            if opts.group('type') in self.data.Structures:
                self.add_structure(cat+":"+opts.group('type'))
                return self.get_data_type(cat, fld_type)
            print("Unable to find a data type for %s".format(opts.group('type')))
            return None

        if opts.group('pointer') is not None:
            data_type = self.dtm.getPointer(data_type)

        if opts.group('array') is not None:
            len = int(opts.group('array')[1:-1])
            array_data_type = ArrayDataType(data_type, len, data_type.length)
            array_data_type.setCategoryPath(CategoryPath(cat))
            data_type = self.dtm.addDataType(array_data_type,DataTypeConflictHandler.DEFAULT_HANDLER)

        return data_type

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
                print("WARNING: Unable to add typedef %s as failed to find data type %s".format(tdef, name))
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
                print("WARNING: Unable to add field %s:%s due no matching data type for %s".format(name, f[1], f[0]))
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


file_to_import = askFile("Choose STM definition file", "Load STM Definitions File")
importer = StmImporter(str(file_to_import))
importer.import_all()
