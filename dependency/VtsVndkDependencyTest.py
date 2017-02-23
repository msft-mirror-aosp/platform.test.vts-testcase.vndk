#!/usr/bin/env python3.4
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

import logging
import os
import re
import shutil
import tempfile

from vts.runners.host import asserts
from vts.runners.host import base_test_with_webdb
from vts.runners.host import test_runner
from vts.utils.python.controllers import android_device
from vts.testcases.vndk.dependency import elf_parser

class VtsVndkDependencyTest(base_test_with_webdb.BaseTestWithWebDbClass):
    """A test case to verify vendor library dependency.

    Attributes:
        _temp_dir: The temporary directory to which the vendor partition is
            copied.
        _vendor_libs: Collection of strings. The names of the shared libraries
            on vendor partition.
    """
    _SHELL_NAME = "vendor_dep_test_shell"
    _VENDOR_PATH = "/vendor"
    _SAME_PROCESS_DIR_32 = "/vendor/lib/sameprocess"
    _SAME_PROCESS_DIR_64 = "/vendor/lib64/sameprocess"
    _LOW_LEVEL_NDK = [
        "libc.so",
        "libm.so",
        "libz.so",
        "liblog.so",
        "libdl.so",
        "libstdc++.so"
    ]
    _SAME_PROCESS_NDK = [re.compile(p) for p in [
        "libEGL_.*\\.so$",
        "libGLESv1_CM_.*\\.so$",
        "libGLESv2_.*\\.so$",
        "libGLESv3_.*\\.so$",
        "vulkan.*\\.so$",
        "libRSDriver.*\\.so$",
        "libPVRRS\\.so$",
        "android\\.hardware\\.graphics\\.mapper@\\d+\\.\\d+-impl\\.so$"
    ]]

    def setUpClass(self):
        """Initializes device and temporary directory."""
        self.dut = self.registerController(android_device)[0]
        self.dut.shell.InvokeTerminal(self._SHELL_NAME)
        self._temp_dir = tempfile.mkdtemp()
        logging.info("adb pull %s %s", self._VENDOR_PATH, self._temp_dir)
        pull_output = self.dut.adb.pull(self._VENDOR_PATH, self._temp_dir)
        logging.debug(pull_output)
        self._vendor_libs = self._listSharedLibraries(self._temp_dir)
        logging.info("Vendor libraries: " + str(self._vendor_libs))

    def tearDownClass(self):
        """Deletes the temporary directory."""
        logging.info("Delete %s", self._temp_dir)
        shutil.rmtree(self._temp_dir)

    def _isSameProcessLibrary(self, lib_name):
        """Checks whether a library is same-process.

        Args:
            lib_name: String. The name of the library.

        Returns:
            A boolean representing whether the library is same-process.
        """
        for pattern in self._SAME_PROCESS_NDK:
            if pattern.match(lib_name):
                return True
        return False

    def _isAllowedDependency(self, lib_name):
        """Checks whether a library dependency is allowed.

        A vendor library/executable is only allowed to depend on
        - Low-level NDK
        - Same-process NDK
        - Other libraries on vendor partition

        Args:
            lib_name: String. The name of the depended library.

        Returns:
            A boolean representing whether the library is allowed.
        """
        if lib_name in self._vendor_libs or lib_name in self._LOW_LEVEL_NDK:
            return True
        if self._isSameProcessLibrary(lib_name):
            return True
        return False

    @staticmethod
    def _iterateFiles(dir_path):
        """A generator yielding regular files in a directory recursively.

        Args:
            dir_path: String. The path to search.

        Yields:
            A tuple of strings (directory, file). The directory containing
            the file and the file name.
        """
        for root_dir, dir_names, file_names in os.walk(dir_path):
            for file_name in file_names:
                yield root_dir, file_name

    @staticmethod
    def _listSharedLibraries(path):
        """Finds all shared libraries under a directory.

        Args:
            path: String. The path to search.

        Returns:
            Set of strings. The names of the found libraries.
        """
        results = set()
        for root_dir, file_name in VtsVndkDependencyTest._iterateFiles(path):
            if file_name.endswith(".so"):
                results.add(file_name)
        return results

    def testSameProcessLibrary(self):
        """Checks if same-process directory contains only allowed libraries."""
        dev_sp_dirs = [self._SAME_PROCESS_DIR_32]
        if self.dut.is64Bit:
            dev_sp_dirs.append(self._SAME_PROCESS_DIR_64)
        error_count = 0
        for dev_sp_dir in dev_sp_dirs:
            sp_dir = os.path.join(self._temp_dir, dev_sp_dir)
            if not os.path.isdir(sp_dir):
                logging.warning("%s is not a directory", sp_dir)
                continue
            logging.info("Enter %s", sp_dir)
            for root_dir, file_name in self._iterateFiles(sp_dir):
                full_path = os.path.join(root_dir, file_name)
                if self._isSameProcessLibrary(file_name):
                    logging.info("%s is a same-process lib", full_path)
                    continue
                error_count += 1
                logging.error("%s is not a same-process lib", full_path)
        asserts.assertEqual(error_count, 0,
                "Total number of errors: " + str(error_count))

    def testElfDependency(self):
        """Scans library/executable dependency on vendor partition."""
        if not elf_parser.ElfParser.isSupported():
            asserts.fail("readelf is not available")
        error_count = 0
        for root_dir, file_name in self._iterateFiles(self._temp_dir):
            file_path = os.path.join(root_dir, file_name)
            elf = elf_parser.ElfParser(file_path)
            if not elf.isValid():
                logging.info("%s is not an ELF file", file_path)
                continue
            try:
                dep_libs = elf.listDependencies()
            except OSError as e:
                error_count += 1
                logging.exception("Cannot read %s: %s", file_path, str(e))
                continue
            logging.info("%s depends on: %s", file_path, str(dep_libs))
            disallowed_libs = filter(
                    lambda x: not self._isAllowedDependency(x), dep_libs)
            if not disallowed_libs:
                continue
            error_count += 1
            logging.error("%s depends on disallowed libs: %s",
                    file_path.replace(self._temp_dir, "", 1),
                    str(disallowed_libs))
        asserts.assertEqual(error_count, 0,
                "Total number of errors: " + str(error_count))

if __name__ == "__main__":
    test_runner.main()

