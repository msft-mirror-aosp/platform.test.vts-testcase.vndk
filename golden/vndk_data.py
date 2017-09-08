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

import csv
import logging
import os

# The tags in VNDK spreadsheet:
# Low-level NDK libraries that can be used by framework and vendor modules.
LL_NDK = "LL-NDK"

# LL-NDK dependencies that vendor modules cannot directly access.
LL_NDK_INDIRECT = "LL-NDK-Indirect"

# Same-process NDK libraries that can be used by framework and vendor modules.
SP_NDK = "SP-NDK"

# SP-NDK dependencies that vendor modules cannot directly access.
SP_NDK_INDIRECT = "SP-NDK-Indirect"

# Framework libraries that can be used by vendor modules except same-process HAL
# and its dependencies in vendor partition.
VNDK = "VNDK"

# Same-process HAL dependencies in framework.
VNDK_SP = "VNDK-SP"

# VNDK-SP dependencies that same-process HAL and its dependencies in vendor
# partition cannot directly access. Other vendor modules can access them.
VNDK_SP_INDIRECT = "VNDK-SP-Indirect"

# VNDK-SP dependencies that vendor modules cannot directly access.
VNDK_SP_INDIRECT_PRIVATE = "VNDK-SP-Indirect-Private"


# The data directory.
_GOLDEN_DIR = os.path.join("vts", "testcases", "vndk", "golden")


def LoadVndkLibraryLists(data_file_path, version, *tags):
    """Find the VNDK libraries with specific tags.

    Args:
        data_file_path: The path to VTS data directory.
        version: A string, the VNDK version.
        *tags: Strings, the tags of the libraries to find.

    Returns:
        A tuple of lists containing library names. Each list corresponds to
        one tag in the argument.
        None if the spreadsheet for the version is not found.
    """
    path = os.path.join(data_file_path, _GOLDEN_DIR, version,
                        "eligible-list.csv")
    if not os.path.isfile(path):
        logging.warning("Cannot load %s.", path)
        return None

    vndk_lists = tuple([] for x in tags)
    with open(path) as csv_file:
        # Skip header
        next(csv_file)
        reader = csv.reader(csv_file)
        for cells in reader:
            for tag_index, tag in enumerate(tags):
                if tag == cells[1]:
                    vndk_lists[tag_index].extend(cells[0].replace("${LIB}", lib)
                                                 for lib in ("lib", "lib64"))
    return vndk_lists
