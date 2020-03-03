#!/usr/bin/env python
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

# TODO(b/147454897): Keep the logic in sync with
#                    test/vts/utils/python/controllers/android_device.py until
#                    it is removed.
import logging
import subprocess

class AndroidDevice(object):
    """This class controls the device via adb commands."""

    def __init__(self, serial_number):
        self._serial_number = serial_number

    def AdbPull(self, src, dst):
        cmd = ["adb", "-s", self._serial_number, "pull", src, dst]
        subprocess.check_call(cmd, shell=False, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _ExecuteCommand(self, *args):
        """Executes a command.

        Args:
            args: Strings, the arguments.

        Returns:
            Stdout as a string, stderr as a string, and return code as an
            integer.
        """
        cmd = ["adb", "-s", self._serial_number, "shell"]
        cmd.extend(args)
        proc = subprocess.Popen(cmd, shell=False, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        # Compatible with python2 and python3
        if not isinstance(out, str):
            out = out.decode("utf-8")
        if not isinstance(err, str):
            err = err.decode("utf-8")
        return out, err, proc.returncode

    def _GetProp(self, name):
        """Gets an Android system property.

        Args:
            name: A string, the property name.

        Returns:
            A string, the value of the property.

        Raises:
            IOError if the command fails.
        """
        out, err, return_code = self._ExecuteCommand("getprop", name)
        if err.strip() or return_code != 0:
            raise IOError("`getprop %s` stdout: %s\nstderr: %s" %
                          (name, out, err))
        return out.strip()

    def GetCpuAbiList(self, bitness=""):
        """Gets the list of supported ABIs from property.

        Args:
            bitness: 32 or 64. If the argument is not specified, this method
                     returns both 32 and 64-bit ABIs.

        Returns:
            A list of strings, the supported ABIs.
        """
        out = self._GetProp("ro.product.cpu.abilist" + str(bitness))
        return out.lower().split(",") if out else []

    def GetLaunchApiLevel(self):
        """Gets the API level that the device was initially launched with.

        This method reads ro.product.first_api_level from the device. If the
        value is 0, it then reads ro.build.version.sdk.

        Returns:
            An integer, the API level.
        """
        level_str = self._GetProp("ro.product.first_api_level")
        level = int(level_str)
        if level != 0:
            return level

        level_str = self._GetProp("ro.build.version.sdk")
        return int(level_str)

    def getLaunchApiLevel(self, strict=True):
        """Gets the API level that the device was initially launched with.

        This method is compatible with vndk_utils in vts package.

        Args:
            strict: A boolean, whether to raise an error if the property is
                    not an integer or not defined.

        Returns:
            An integer, the API level.
            0 if the value is undefined and strict is False.

        Raises:
            ValueError: if the value is undefined and strict is True.
        """
        try:
            return self.GetLaunchApiLevel()
        except ValueError as e:
            if strict:
                raise
            logging.exception(e)
            return 0

    @property
    def vndk_lite(self):
        """Checks whether the vendor partition requests lite VNDK enforcement.

        This method is compatible with vndk_utils in vts package.

        Returns:
            A boolean, True for lite vndk enforcement.
        """
        return self._GetProp("ro.vndk.lite").lower() == "true"

    def GetVndkVersion(self):
        """Gets the VNDK version that the vendor partition requests."""
        return self._GetProp("ro.vndk.version")

    def IsRoot(self):
        """Returns whether adb has root privilege on the device."""
        out, err, return_code = self._ExecuteCommand("id")
        if err.strip() or return_code != 0:
            raise IOError("`id` stdout: %s\nstderr: %s \n" % (out, err))
        return "uid=0(root)" in out.strip()

    def _Test(self, *args):
        """Tests file types and status."""
        out, err, return_code = self._ExecuteCommand("test", *args)
        if out.strip() or err.strip():
            raise IOError("`test` args: %s\nstdout: %s\nstderr: %s" %
                          (args, out, err))
        return return_code == 0

    def IsDirectory(self, path):
        """Returns whether a path on the device is a directory."""
        return self._Test("-d", path)

    def _Stat(self, fmt, path):
        """Executes stat command."""
        out, err, return_code = self._ExecuteCommand("stat", "--format", fmt,
                                                     path)
        if return_code != 0 or err.strip():
            raise IOError("`stat --format %s %s` stdout: %s\nstderr: %s" %
                          (fmt, path, out, err))
        return out.strip()

    def IsExecutable(self, path):
        """Returns if execute permission is granted to a path on the device."""
        return "x" in self._Stat("%A", path)
