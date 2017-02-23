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

import os
import re

from vts.runners.host import utils

class ElfParser(object):
    """This class reads an ELF file by parsing output of the command readelf.

    Attributes:
        _file_path: The path to the ELF file.
    """

    def __init__(self, file_path):
        self._file_path = file_path

    @staticmethod
    def isSupported():
        """Checks whether readelf is available."""
        try:
            utils.exe_cmd("readelf", "--version")
            return True
        except OSError:
            return False

    def isValid(self):
        """Checks size and first 4 bytes of the ELF file.

        Returns:
            A boolean representing whether _file_path is a valid ELF.
        """
        try:
            size = os.path.getsize(self._file_path)
            # must be larger than 32-bit file header
            if size < 52:
                return False
        except OSError:
            return False
        try:
            with open(self._file_path, "rb") as f:
                magic = f.read(4)
                if list(bytearray(magic)) != [0x7f, 0x45, 0x4c, 0x46]:
                    return False
        except IOError:
            return False
        return True

    def listDependencies(self):
        """Lists the shared libraries that the ELF depends on.

        Returns:
            List of strings. The names of the depended libraries.

        Raises:
            OSError if readelf fails.
        """
        pattern = re.compile("\\(NEEDED\\)\\s*Shared library: \[(.+)\]")
        output = utils.exe_cmd("readelf", "--dynamic", self._file_path)
        results = []
        for line in output.split("\n"):
            match = pattern.search(line)
            if match:
                results.append(match.group(1))
        return results

