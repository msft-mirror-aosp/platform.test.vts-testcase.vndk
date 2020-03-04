#!/usr/bin/env python3
#
# Copyright (C) 2020 The Android Open Source Project
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
import posixpath as target_path_module
import re
import unittest

from vts.testcases.vndk import utils
from vts.testcases.vndk.golden import vndk_data
from vts.utils.python.vndk import vndk_utils


class VtsVndkOpenLibrariesTest(unittest.TestCase):
    """A test module to verify libraries opened by running processes.

    Attributes:
        _dut: The AndroidDevice under test.
    """

    def setUp(self):
        """Initializes attributes."""
        serial_number = os.environ.get("ANDROID_SERIAL")
        self.assertTrue(serial_number, "$ANDROID_SERIAL is empty.")
        self._dut = utils.AndroidDevice(serial_number)

    def _ListProcessCommands(self, cmd_filter):
        """Finds current processes whose commands match the filter.

        Args:
            cmd_filter: A function that takes a binary file path as argument
                        and returns whether the path matches the condition.

        Returns:
            A dict of {pid: command} where pid and command are strings.
        """
        ps_cmd = ["ps", "-Aw", "-o", "PID,COMMAND"]
        out, err, return_code = self._dut.Execute(*ps_cmd)
        if err.strip():
            logging.info("`%s` stderr: %s", " ".join(ps_cmd), err)
        self.assertEqual(return_code, 0)

        lines = out.split("\n")
        pid_end = lines[0].index("PID") + len("PID")
        cmd_begin = lines[0].index("COMMAND", pid_end)
        cmds = {}
        for line in lines[1:]:
            cmd = line[cmd_begin:]
            if not cmd_filter(cmd):
                continue
            pid = line[:pid_end].lstrip()
            cmds[pid] = cmd
        return cmds

    def _ListOpenFiles(self, pids, file_filter):
        """Finds open files whose names match the filter.

        Args:
            pids: A collection of strings, the PIDs to list open files.
            file_filter: A function that takes a file path as argument and
                         returns whether the path matches the condition.

        Returns:
            A dict of {pid: [file, ...]} where pid and file are strings.
        """
        lsof_cmd = ["lsof", "-p", ",".join(pids)]
        out, err, return_code = self._dut.Execute(*lsof_cmd)
        if err.strip():
            logging.info("`%s` stderr: %s", " ".join(lsof), err)
        self.assertEqual(return_code, 0)
        # The first line consists of the column names:
        # COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        # PID is right-justified. NAME is left-justified.
        lines = out.split("\n")
        pid_end = lines[0].index("PID") + len("PID")
        name_begin = lines[0].index("NAME")
        files = {}
        for line in lines[1:]:
            if not line.strip():
                continue
            # On Android, COMMAND may exceed the column and causes the right
            # columns to be misaligned. This program looks for digits in the
            # PID column or on the right of the column.
            try:
                match_pid = next(match for match in
                                 re.finditer(r"\s(\d+)\s", line) if
                                 match.end(1) >= pid_end)
            except StopIteration:
                self.fail("Cannot parse PID from lsof output: " + line)
            offset = match_pid.end(1) - pid_end
            self.assertEqual(line[name_begin + offset - 1], " ",
                             "Cannot parse NAME from lsof output: " + line)
            name = line[name_begin + offset:]
            if not file_filter(name):
                continue
            pid = match_pid.group(1)
            if pid in files:
                files[pid].append(name)
            else:
                files[pid] = [name]
        return files

    def testVendorProcessOpenLibraries(self):
        """Checks if vendor processes load shared libraries on system."""
        if not vndk_utils.IsVndkRuntimeEnforced(self._dut):
            logging.info("Skip the test as VNDK runtime is not enforced on "
                         "the device.")
            return
        vndk_lists = vndk_data.LoadVndkLibraryListsFromResources(
            self._dut.GetVndkVersion(),
            vndk_data.LL_NDK,
            vndk_data.LL_NDK_PRIVATE,
            vndk_data.VNDK,
            vndk_data.VNDK_PRIVATE,
            vndk_data.VNDK_SP,
            vndk_data.VNDK_SP_PRIVATE)
        self.assertTrue(vndk_lists, "Cannot load VNDK library lists.")
        allowed_libs = set().union(*vndk_lists)
        logging.debug("Allowed system libraries: %s", allowed_libs)

        self.assertTrue(self._dut.IsRoot(),
                        "Must be root to find all libraries in use.")
        cmds = self._ListProcessCommands(lambda x: (x.startswith("/odm/") or
                                                    x.startswith("/vendor/")))

        def _IsDisallowedSystemLib(lib_path):
            return ((lib_path.startswith("/system/") or
                     lib_path.startswith("/apex/")) and
                    lib_path.endswith(".so") and
                    target_path_module.basename(lib_path) not in allowed_libs)

        deps = self._ListOpenFiles(cmds.keys(), _IsDisallowedSystemLib)
        if deps:
            error_lines = ["%s %s %s" % (pid, cmds[pid], libs)
                           for pid, libs in deps.items()]
            logging.error("pid command libraries\n%s", "\n".join(error_lines))

            assert_lines = ["pid command libraries"] + error_lines[:20]
            if len(deps) > 20:
                assert_lines.append("...")
            assert_lines.append("Number of vendor processes using system "
                                "libraries: " + str(len(deps)))
            self.fail("\n".join(assert_lines))


if __name__ == "__main__":
    unittest.main()
