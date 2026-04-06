import pathlib
from functional import seq
from collections.abc import Iterable

class dict_fromhex(dict):
# dict overload that returns bytes directly from hex string values

    def __getitem__(self, key):

        # type exceptions to skip the hex conversion:
        allowed_types = {"str": str, "int": int, "float": float, "bool": lambda x: x}

        raw_return = super().__getitem__(key)
        if isinstance(raw_return, dict):
            if "type" in raw_return and "value" in raw_return:
                return allowed_types[raw_return["type"]](raw_return["value"])
            else:
                raise KeyError(f"Expected a 2-value dict with 'value' and 'type' keys, got: {raw_return}")
        else:
            return bytes.fromhex(super().__getitem__(key))

class file_entry_manager:
# class to manage what's in the encryption list

    base_entries:list[pathlib.Path]
    file_path:pathlib.Path

    def __init__(self, file_path:pathlib.Path):
        
        # if it wasn't a Path before, it is now:
        if not isinstance(file_path, pathlib.Path):
            file_path  = pathlib.Path(file_path)

        if not file_path.is_file():
            file_path.touch() #now it exists, too!

        self.file_path = file_path

        with self.file_path.open("r") as file:
            self.base_entries = seq(file.readlines()).filter(lambda x: len(x.strip()) > 0).map(lambda line: line.rstrip("\n"))

        self.base_entries = self.base_entries.map(pathlib.Path).filter(lambda x: x.exists())
        self.get_subentries()
        
    def get_subentries(self):
    # expands folders into lists of files

        self.entries = self.base_entries.map(pathlib.Path.absolute)

        bad_entries = seq([])
        for ii in range(1, self.entries.len()):
            if self.entries[ii] in list(self.entries[ii-1].rglob("*")):
                bad_entries += [self.entries[ii]]

        temp = self.entries[::-1]
        for ii in range(1, self.entries.len()):
            if temp[ii] in list(temp[ii-1].rglob("*")):
                bad_entries += [temp[ii]]

        for bad in bad_entries:
            self.base_entries = self.base_entries.filter_not(lambda x: x==bad)

        # cleanup raw text:
        if self.entries.map(lambda x: str(x).find("file_encryptor") != -1).any():
            raise ValueError("file_encryptor cannot be in the list.")
        
        if self.entries.filter(pathlib.Path.is_file).any():
            raise TypeError("Files are not allowed in the batch encryption list.")
        
        # we have no files in self.entries. Expand self.entries to show all its nested subfiles
        dir_entries = (self.entries.map(lambda x: x.rglob("*")) # recursively list all subfiles
            .flatten() # flatten nested lists
            .filter(pathlib.Path.is_file) # filter to files only now
        )

        self.entries = dir_entries

    def add_item(self, new_items:Iterable[pathlib.Path] | pathlib.Path) -> None:
    # adds an item to the text file in a newline

        if isinstance(new_items, Iterable) and len(new_items[0])!=1:
            for ele in new_items:
                if ele not in self.base_entries and ele not in self.base_entries.flat_map(lambda x: x.rglob("*")):
                    self.base_entries += seq(ele)
        
        else:
            if (ele:=new_items) not in self.base_entries and ele not in self.base_entries.flat_map(lambda x: x.rglob("*")):
                self.base_entries += seq([ele])

        self.save_file()
        self.get_subentries()

    def remove_item(self, items_to_remove:Iterable[pathlib.Path] | pathlib.Path) -> None:
    # remover

        if isinstance(items_to_remove, Iterable) and len(items_to_remove[0])!=1:
            for ele in items_to_remove:
                if ele in self.base_entries:
                    self.base_entries = self.base_entries.filter_not(lambda x: x == ele)
        else:
            if (ele:=items_to_remove) in self.base_entries:
                self.base_entries = self.base_entries.filter_not(lambda x: x == ele)

        self.save_file()
        self.get_subentries()

    def save_file(self):
    # write the file out to save

        with self.file_path.open("w") as file:
            seq(self.base_entries).map(lambda x: str(x)+"\n").for_each(file.write)


def main():
    pass

if __name__ == "__main__":
    main()