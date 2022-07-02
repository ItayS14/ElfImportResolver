import lief
import json
import argparse
from collections import defaultdict
import os


class ElfFile:
    def __init__(self, file_path, rel_path):
        self._file_path = file_path
        self._binary = lief.parse(self._file_path)
        self.rel_path = rel_path
        if self._binary is None:
            raise Exception(f"Invalid ElfFile {self.rel_path}")

    @property
    def exported_functions(self):
        return (symbol.name for symbol in self._binary.exported_functions)

    @property
    def machine_type(self):
        machine_type_data = self._binary.header.machine_type
        return {
            "name": machine_type_data.name,
            "value": machine_type_data.value
        }

def elf_files_generator(root_directory):
    for root, _, files in os.walk(root_directory):
        for file in files:
            try:
                yield ElfFile(os.path.join(root, file), os.path.join(root.split(root_directory)[1][1:], file))
            except Exception as e:
                print(e) 

def create_exported_mapping_dict(base_directory):
    exported_mapping_dict = defaultdict(lambda : [])

    for elf_file in elf_files_generator(base_directory):
        print(f'Parsing: {elf_file.rel_path}')
        for exported_function in elf_file.exported_functions:
            machine_type = elf_file.machine_type
            exported_mapping_dict[exported_function].append({
                "path": elf_file.rel_path,
                "arch": machine_type
            }) 

    return exported_mapping_dict

def main():
    parser = argparse.ArgumentParser(description="Dump exported funcntions from SO's into json")
    parser.add_argument("directory", type=str, help="Directory of the SO's to dump exported functions")
    parser.add_argument("output_file", type=str, help="Output json file")

    args = parser.parse_args()

    exported_mapping_dict = create_exported_mapping_dict(args.directory)

    with open(args.output_file, "w") as f:
        f.write(json.dumps(exported_mapping_dict, indent=2))

if __name__ == '__main__':
    main()
