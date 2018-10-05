#!/usr/bin/env python
#
# Copyright (C) 2017 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import json
import logging
import os
import shutil
import tempfile

from vts.runners.host import asserts
from vts.runners.host import base_test
from vts.runners.host import const
from vts.runners.host import keys
from vts.runners.host import test_runner
from vts.testcases.vndk.golden import vndk_data
from vts.utils.python.library import elf_parser
from vts.utils.python.library.vtable import vtable_dumper


def _IterateFiles(root_dir):
    """A generator yielding relative and full paths in a directory.

    Args:
        root_dir: The directory to search.

    Yields:
        A tuple of (relative_path, full_path) for each regular file.
        relative_path is the relative path to root_dir. full_path is the path
        starting with root_dir.
    """
    for dir_path, dir_names, file_names in os.walk(root_dir):
        if dir_path == root_dir:
            rel_dir = ""
        else:
            rel_dir = os.path.relpath(dir_path, root_dir)
        for file_name in file_names:
            yield (os.path.join(rel_dir, file_name),
                   os.path.join(dir_path, file_name))


class VtsVndkAbiTest(base_test.BaseTestClass):
    """A test module to verify ABI compliance of vendor libraries.

    Attributes:
        _dut: the AndroidDevice under test.
        _temp_dir: The temporary directory for libraries copied from device.
        _vndk_version: String, the VNDK version supported by the device.
        data_file_path: The path to VTS data directory.
    """
    _ODM_LIB_DIR_32 = "/odm/lib"
    _ODM_LIB_DIR_64 = "/odm/lib64"
    _VENDOR_LIB_DIR_32 = "/vendor/lib"
    _VENDOR_LIB_DIR_64 = "/vendor/lib64"
    _SYSTEM_LIB_DIR_32 = "/system/lib"
    _SYSTEM_LIB_DIR_64 = "/system/lib64"

    def setUpClass(self):
        """Initializes data file path, device, and temporary directory."""
        required_params = [keys.ConfigKeys.IKEY_DATA_FILE_PATH]
        self.getUserParams(required_params)
        self._dut = self.android_devices[0]
        self._temp_dir = tempfile.mkdtemp()
        self._vndk_version = self._dut.vndk_version

    def tearDownClass(self):
        """Deletes the temporary directory."""
        logging.info("Delete %s", self._temp_dir)
        shutil.rmtree(self._temp_dir)

    def _PullOrCreateDir(self, target_dir, host_dir):
        """Copies a directory from device. Creates an empty one if not exist.

        Args:
            target_dir: The directory to copy from device.
            host_dir: The directory to copy to host.
        """
        test_cmd = "test -d " + target_dir
        logging.info("adb shell %s", test_cmd)
        result = self._dut.adb.shell(test_cmd, no_except=True)
        if result[const.EXIT_CODE]:
            logging.info("%s doesn't exist. Create %s.", target_dir, host_dir)
            os.mkdir(host_dir, 0750)
            return
        logging.info("adb pull %s %s", target_dir, host_dir)
        self._dut.adb.pull(target_dir, host_dir)

    @staticmethod
    def _LoadGlobalSymbolsFromDump(dump_obj):
        """Loads global symbols from a dump object.

        Args:
            dump_obj: A dict, the dump in JSON format.

        Returns:
            A set of strings, the symbol names.
        """
        symbols = set()
        for key in ("elf_functions", "elf_objects"):
            symbols.update(
                symbol.get("name", "") for symbol in dump_obj.get(key, []) if
                symbol.get("binding", "global") == "global")
        return symbols

    def _DiffElfSymbols(self, dump_obj, parser):
        """Checks if a library includes all symbols in a dump.

        Args:
            dump_obj: A dict, the dump in JSON format.
            parser: An elf_parser.ElfParser that loads the library.

        Returns:
            A list of strings, the global symbols that are in the dump but not
            in the library.

        Raises:
            elf_parser.ElfError if fails to load the library.
        """
        dump_symbols = self._LoadGlobalSymbolsFromDump(dump_obj)
        lib_symbols = parser.ListGlobalDynamicSymbols(include_weak=True)
        return sorted(dump_symbols.difference(lib_symbols))

    @staticmethod
    def _DiffVtableComponent(offset, expected_symbol, vtable):
        """Checks if a symbol is in a vtable entry.

        Args:
            offset: An integer, the offset of the expected symbol.
            exepcted_symbol: A string, the name of the expected symbol.
            vtable: A dict of {offset: [entry]} where offset is an integer and
                    entry is an instance of vtable_dumper.VtableEntry.

        Returns:
            A list of strings, the actual possible symbols if expected_symbol
            does not match the vtable entry.
            None if expected_symbol matches the entry.
        """
        if offset not in vtable:
            return []

        entry = vtable[offset]
        if not entry.names:
            return [hex(entry.value).rstrip('L')]

        if expected_symbol not in entry.names:
            return entry.names

    def _DiffVtableComponents(self, dump_obj, dumper):
        """Checks if a library includes all vtable entries in a dump.

        Args:
            dump_obj: A dict, the dump in JSON format.
            dumper: An vtable_dumper.VtableDumper that loads the library.

        Returns:
            A list of tuples (VTABLE, OFFSET, EXPECTED_SYMBOL, ACTUAL).
            ACTUAL can be "missing", a list of symbol names, or an ELF virtual
            address.

        Raises:
            vtable_dumper.VtableError if fails to dump vtable from the library.
        """
        function_kinds = [
            "function_pointer",
            "complete_dtor_pointer",
            "deleting_dtor_pointer"
        ]
        non_function_kinds = [
            "vcall_offset",
            "vbase_offset",
            "offset_to_top",
            "rtti",
            "unused_function_pointer"
        ]
        default_vtable_component_kind = "function_pointer"

        global_symbols = self._LoadGlobalSymbolsFromDump(dump_obj)

        lib_vtables = {vtable.name: vtable
                       for vtable in dumper.DumpVtables()}
        logging.debug("\n\n".join(str(vtable)
                                  for _, vtable in lib_vtables.iteritems()))

        vtables_diff = []
        for record_type in dump_obj.get("record_types", []):
            type_name_symbol = record_type.get("unique_id", "")
            vtable_symbol = type_name_symbol.replace("_ZTS", "_ZTV", 1)

            # Skip if the vtable symbol isn't global.
            if vtable_symbol not in global_symbols:
                continue

            # Collect vtable entries from library dump.
            if vtable_symbol in lib_vtables:
                lib_vtable = {entry.offset: entry
                              for entry in lib_vtables[vtable_symbol].entries}
            else:
                lib_vtable = dict()

            for index, entry in enumerate(record_type.get("vtable_components",
                                                          [])):
                entry_offset = index * int(self.abi_bitness) // 8
                entry_kind = entry.get("kind", default_vtable_component_kind)
                entry_symbol = entry.get("mangled_component_name", "")
                entry_is_pure = entry.get("is_pure", False)

                if entry_kind in non_function_kinds:
                    continue

                if entry_kind not in function_kinds:
                    logging.warning("%s: Unexpected vtable entry kind %s",
                                    vtable_symbol, entry_kind)

                if entry_symbol not in global_symbols:
                    # Itanium cxx abi doesn't specify pure virtual vtable
                    # entry's behaviour. However we can still do some checks
                    # based on compiler behaviour.
                    # Even though we don't check weak symbols, we can still
                    # issue a warning when a pure virtual function pointer
                    # is missing.
                    if entry_is_pure and entry_offset not in lib_vtable:
                        logging.warning("%s: Expected pure virtual function"
                                        "in %s offset %s",
                                        vtable_symbol, vtable_symbol,
                                        entry_offset)
                    continue

                diff_symbols = self._DiffVtableComponent(
                    entry_offset, entry_symbol, lib_vtable)
                if diff_symbols is None:
                    continue

                vtables_diff.append(
                    (vtable_symbol, str(entry_offset), entry_symbol,
                     (",".join(diff_symbols) if diff_symbols else "missing")))

        return vtables_diff

    def _ScanLibDirs(self, dump_dir, lib_dirs, dump_version):
        """Compares dump files with libraries copied from device.

        Args:
            dump_dir: The directory containing dump files.
            lib_dirs: The list of directories containing libraries.
            dump_version: The VNDK version of the dump files. If the device has
                          no VNDK version or has extension in vendor partition,
                          this method compares the unversioned VNDK directories
                          with the dump directories of the given version.

        Returns:
            An integer, number of incompatible libraries.
        """
        error_count = 0
        dump_paths = dict()
        lib_paths = dict()
        for dump_rel_path, dump_path in _IterateFiles(dump_dir):
            if dump_rel_path.endswith(".dump"):
                lib_name = dump_rel_path.rpartition(".dump")[0]
                dump_paths[lib_name] = dump_path
            else:
                logging.warning("Unknown dump: %s", dump_path)
                continue
            lib_paths[lib_name] = None

        for lib_dir in lib_dirs:
            for lib_rel_path, lib_path in _IterateFiles(lib_dir):
                try:
                    vndk_dir = next(x for x in ("vndk", "vndk-sp") if
                                    lib_rel_path.startswith(x + os.path.sep))
                    lib_name = lib_rel_path.replace(
                        vndk_dir, vndk_dir + "-" + dump_version, 1)
                except StopIteration:
                    lib_name = lib_rel_path

                if lib_name in lib_paths and not lib_paths[lib_name]:
                    lib_paths[lib_name] = lib_path

        for lib_name, lib_path in lib_paths.iteritems():
            if not lib_path:
                logging.info("%s: Not found on target", lib_name)
                continue
            rel_path = os.path.relpath(lib_path, self._temp_dir)

            has_exception = False
            missing_symbols = []
            vtable_diff = []

            if lib_name in dump_paths:
                try:
                    with open(dump_paths[lib_name], "r") as dump_file:
                        dump_obj = json.load(dump_file)
                    with vtable_dumper.VtableDumper(lib_path) as dumper:
                        missing_symbols = self._DiffElfSymbols(
                            dump_obj, dumper)
                        vtable_diff = self._DiffVtableComponents(
                            dump_obj, dumper)
                except (IOError,
                        elf_parser.ElfError,
                        vtable_dumper.VtableError) as e:
                    logging.exception("%s: Cannot diff ABI", rel_path)
                    has_exception = True

            if missing_symbols:
                logging.error("%s: Missing Symbols:\n%s",
                              rel_path, "\n".join(missing_symbols))
            if vtable_diff:
                logging.error("%s: Vtable Difference:\n"
                              "vtable offset expected actual\n%s",
                              rel_path,
                              "\n".join(" ".join(e) for e in vtable_diff))
            if (has_exception or missing_symbols or vtable_diff):
                error_count += 1
            else:
                logging.info("%s: Pass", rel_path)
        return error_count

    def testAbiCompatibility(self):
        """Checks ABI compliance of VNDK libraries."""
        primary_abi = self._dut.getCpuAbiList()[0]
        binder_bitness = self._dut.getBinderBitness()
        asserts.assertTrue(binder_bitness,
                           "Cannot determine binder bitness.")
        dump_version = (self._vndk_version if self._vndk_version else
                        vndk_data.LoadDefaultVndkVersion(self.data_file_path))
        asserts.assertTrue(dump_version,
                           "Cannot load default VNDK version.")

        dump_dir = vndk_data.GetAbiDumpDirectory(
            self.data_file_path,
            dump_version,
            binder_bitness,
            primary_abi,
            self.abi_bitness)
        asserts.assertTrue(
            dump_dir,
            "No dump files. version: %s ABI: %s bitness: %s" % (
                self._vndk_version, primary_abi, self.abi_bitness))
        logging.info("dump dir: %s", dump_dir)

        odm_lib_dir = os.path.join(
            self._temp_dir, "odm_lib_dir_" + self.abi_bitness)
        vendor_lib_dir = os.path.join(
            self._temp_dir, "vendor_lib_dir_" + self.abi_bitness)
        system_lib_dir = os.path.join(
            self._temp_dir, "system_lib_dir_" + self.abi_bitness)
        logging.info("host lib dir: %s %s %s",
                     odm_lib_dir, vendor_lib_dir, system_lib_dir)
        self._PullOrCreateDir(
            getattr(self, "_ODM_LIB_DIR_" + self.abi_bitness),
            odm_lib_dir)
        self._PullOrCreateDir(
            getattr(self, "_VENDOR_LIB_DIR_" + self.abi_bitness),
            vendor_lib_dir)
        self._PullOrCreateDir(
            getattr(self, "_SYSTEM_LIB_DIR_" + self.abi_bitness),
            system_lib_dir)

        error_count = self._ScanLibDirs(
            dump_dir, [odm_lib_dir, vendor_lib_dir, system_lib_dir], dump_version)
        asserts.assertEqual(error_count, 0,
                            "Total number of errors: " + str(error_count))


if __name__ == "__main__":
    test_runner.main()
