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

import logging

from vts.runners.host import asserts
from vts.runners.host import base_test
from vts.runners.host import keys
from vts.runners.host import test_runner
from vts.testcases.vndk.golden import vndk_data
from vts.utils.python.file import target_file_utils
from vts.utils.python.vndk import vndk_utils


class VtsVndkFilesTest(base_test.BaseTestClass):
    """A test for VNDK files and directories.

    Attributes:
        data_file_path: The path to VTS data directory.
        _dut: The AndroidDevice under test.
        _shell: The ShellMirrorObject that executes commands.
        _vndk_version: The VNDK version of the device.
    """

    def setUpClass(self):
        """Initializes the data file path and shell."""
        required_params = [keys.ConfigKeys.IKEY_DATA_FILE_PATH]
        self.getUserParams(required_params)
        self._dut = self.android_devices[0]
        self._shell = self._dut.shell
        self._vndk_version = self._dut.vndk_version

    def _ListFiles(self, dir_path):
        """Lists all files in a directory except subdirectories.

        Args:
            dir_path: A string, path to the directory on device.

        Returns:
            A list of strings, the file paths in the directory.
        """
        return target_file_utils.FindFiles(self._shell, dir_path, "*",
                                           "! -type d")

    def _TestVndkDirectory(self, vndk_dir, *vndk_list_names):
        """Verifies that the VNDK directory doesn't contain extra files.

        Args:
            vndk_dir: The path to the VNDK directory on device.
            *vndk_list_names: Strings, the categories of the VNDK libraries
                              that can be in the directory.
        """
        vndk_lists = vndk_data.LoadVndkLibraryLists(
            self.data_file_path, self._vndk_version, *vndk_list_names)
        asserts.assertTrue(vndk_lists, "Cannot load VNDK library lists.")
        vndk_set = set().union(*vndk_lists)
        logging.debug("vndk set: %s", vndk_set)
        unexpected = set(self._ListFiles(vndk_dir)) - vndk_set
        if unexpected:
            logging.error("Unexpected files:\n%s", "\n".join(unexpected))
            asserts.fail("Total number of errors: %d" % len(unexpected))

    def testVndkCoreDirectory(self):
        """Verifies that VNDK-core directory doesn't contain extra files."""
        asserts.skipIf(not vndk_utils.IsVndkRuntimeEnforced(self._dut),
                       "VNDK runtime is not enforced on the device.")
        self._TestVndkDirectory(
            vndk_utils.GetVndkCoreDirectory(
                self.abi_bitness, self._vndk_version),
            vndk_data.VNDK)

    def testVndkSpDirectory(self):
        """Verifies that VNDK-SP directory doesn't contain extra files."""
        self._TestVndkDirectory(
            vndk_utils.GetVndkSpDirectory(
                self.abi_bitness, self._vndk_version),
            vndk_data.VNDK_SP,
            vndk_data.VNDK_SP_INDIRECT,
            vndk_data.VNDK_SP_INDIRECT_PRIVATE)


if __name__ == "__main__":
    test_runner.main()
