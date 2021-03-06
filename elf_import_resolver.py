import json
from collections import defaultdict

import ida_bytes
import ida_idaapi
import ida_nalt
import ida_kernwin
import idc

ELF_ARCH_OFFSET = 0x12
LIBC_VERSION_SEPERATOR = "@@"
REPEATABLE_COMMENT = 1


class ElfImportResolver(ida_idaapi.plugin_t):
    flags = 0
    comment = ""
    wanted_hotkey = ""
    wanted_name = "ImportResolver"
    help = "Add elf names to resolved dynamic imports"

    def init(self):
        print("Initialized ElfImportResolver")
        self._arch_type = ida_bytes.get_word(ida_nalt.get_imagebase() + ELF_ARCH_OFFSET)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, _):
        exported_function_mapping_path = ida_kernwin.ask_file(0, "*.json", "Load json configuration")
        with open(exported_function_mapping_path, "r") as exported_function_mapping_file:
            exported_functions_mapping = defaultdict(list, json.load(exported_function_mapping_file))

        def imported_function_handler(ea, function_name, _):
            idc.set_func_cmt(ea, "Unknown file path", REPEATABLE_COMMENT)

            stripped_func_name = function_name.split(LIBC_VERSION_SEPERATOR)[0]
            for elf_containing_func in exported_functions_mapping[stripped_func_name]:
                if self._arch_type == elf_containing_func["arch"]["value"]:
                    idc.set_func_cmt(ea, elf_containing_func["path"], REPEATABLE_COMMENT)
                    print(f'Found {stripped_func_name} at {elf_containing_func["path"]}')
                    break

            return True

        for module_index in range(ida_nalt.get_import_module_qty()):
            ida_nalt.enum_import_names(module_index, imported_function_handler)


    def term(self):
        pass

def PLUGIN_ENTRY():
    return ElfImportResolver()