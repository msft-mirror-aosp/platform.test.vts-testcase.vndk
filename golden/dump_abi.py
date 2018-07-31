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

import argparse
import gzip
import importlib
import os
import subprocess
import sys

from google.protobuf import text_format

class ExternalModules(object):
    """This class imports modules dynamically and keeps them as attributes.

    Assume the user runs this script in the source directory. The VTS modules
    are outside the search path and thus have to be imported dynamically.

    Attribtues:
        ar_parser: The ar_parser module.
        elf_parser: The elf_parser module.
        vtable_parser: The vtable_parser module.
    """
    @classmethod
    def ImportParsers(cls, build_top_dir):
        """Imports elf_parser and vtable_parser.

        Args:
            build_top_dir: Value of the environment variable ANDROID_BUILD_TOP.
        """
        sys.path.append(os.path.join(build_top_dir, 'test'))
        sys.path.append(os.path.join(build_top_dir, 'test', 'vts-testcase'))
        sys.path.append(os.path.join(build_top_dir, 'development', 'vndk',
                                     'tools', 'header-checker'))
        cls.ar_parser = importlib.import_module(
            "vts.utils.python.library.ar_parser")
        cls.elf_parser = importlib.import_module(
            "vts.utils.python.library.elf_parser")
        cls.vtable_parser = importlib.import_module(
            "vts.utils.python.library.vtable_parser")
        cls.VndkAbiDump = importlib.import_module(
            "vndk.proto.VndkAbiDump_pb2")
        cls.AbiDump = importlib.import_module("proto.abi_dump_pb2")


def _CreateAndWrite(path, data):
    """Creates directories on a file path and writes data to it.

    Args:
        path: The path to the file.
        data: The data to write.
    """
    dir_name = os.path.dirname(path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name)
    with open(path, "w") as f:
        f.write(data)


def _ExecuteCommand(cmd, **kwargs):
    """Executes a command and returns stdout.

    Args:
        cmd: A list of strings, the command to execute.
        **kwargs: The arguments passed to subprocess.Popen.

    Returns:
        A string, the stdout.
    """
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    stdout, stderr = proc.communicate()
    if proc.returncode:
        sys.exit("Command failed: %s\nstdout=%s\nstderr=%s" % (
                 cmd, stdout, stderr))
    if stderr:
        print("Warning: cmd=%s\nstdout=%s\nstderr=%s" % (cmd, stdout, stderr))
    return stdout.strip()


def GetBuildVariables(build_top_dir, abs_path, vars):
    """Gets values of variables from build config.

    Args:
        build_top_dir: The path to root directory of Android source.
        abs_path: A boolean, whether to convert the values to absolute paths.
        vars: A list of strings, the names of the variables.

    Returns:
        A list of strings which are the values of the variables.
    """
    cmd = ["build/soong/soong_ui.bash", "--dumpvars-mode",
           ("--abs-vars" if abs_path else "--vars"), " ".join(vars)]
    stdout = _ExecuteCommand(cmd, cwd=build_top_dir)
    print(stdout)
    return [line.split("=", 1)[1].strip("'") for line in stdout.splitlines()]


def FindBinary(file_name):
    """Finds an executable binary in environment variable PATH.

    Args:
        file_name: The file name to find.

    Returns:
        A string which is the path to the binary.
    """
    return _ExecuteCommand(["which", file_name])


def DumpSymbols(lib_path, dump_path, exclude_symbols):
    """Dump symbols from a library to a dump file.

    The dump file is a sorted list of symbols. Each line contains one symbol.

    Args:
        lib_path: The path to the library.
        dump_path: The path to the dump file.
        exclude_symbols: A set of strings, the symbols that should not be
                         written to the dump file.

    Returns:
        A list of strings which are the symbols written to the dump file.

    Raises:
        elf_parser.ElfError if fails to load the library.
        IOError if fails to write to the dump.
    """
    elf_parser = ExternalModules.elf_parser
    parser = None
    try:
        parser = elf_parser.ElfParser(lib_path)
        symbols = [x for x in parser.ListGlobalDynamicSymbols()
                   if x not in exclude_symbols]
    finally:
        if parser:
            parser.Close()
    if symbols:
        symbols.sort()
        _CreateAndWrite(dump_path, "\n".join(symbols) + "\n")
    return symbols


def DumpVtables(lib_path, dump_path, dumper_dir, include_symbols):
    """Dump vtables from a library to a dump file.

    The dump file is the raw output of vndk-vtable-dumper.

    Args:
        lib_path: The path to the library.
        dump_path: The path to the text file.
        dumper_dir: The path to the directory containing the dumper executable
                    and library.
        include_symbols: A set of strings. A vtable is written to the dump file
                         only if its symbol is in the set.

    Returns:
        A string which is the content written to the dump file.

    Raises:
        vtable_parser.VtableError if fails to load the library.
        IOError if fails to write to the dump.
    """
    vtable_parser = ExternalModules.vtable_parser
    parser = vtable_parser.VtableParser(dumper_dir)

    def GenerateLines():
        for line in parser.CallVtableDumper(lib_path).split("\n"):
            parsed_lines.append(line)
            yield line

    lines = GenerateLines()
    dump_lines = []
    try:
        while True:
            parsed_lines = []
            vtable, entries = parser.ParseOneVtable(lines)
            if vtable in include_symbols:
                dump_lines.extend(parsed_lines)
    except StopIteration:
        pass

    dump_string = "\n".join(dump_lines).strip("\n")
    if dump_string:
        dump_string += "\n"
        _CreateAndWrite(dump_path, dump_string)
    return dump_string


def DumpVtablesFromLsdump(lib_lsdump_path, dump_path, include_symbols,
                          abi_bitness):
    """Dump vtables from a lsdump to a dump file.

    The dump file is a vts.proto.VndkAbiDump_pb2.AbiDump() message.

    Args:
        lib_lsdump_path: The path to the (gzipped) lsdump file.
        dump_path: The path to the output text file.
        include_symbols: A set of strings. A vtable is written to the dump file
                         only if its symbol is in the set.
        abi_bitness: A string describing the bitness of the target abi. The
                     value should be '32' or '64'.

    Returns:
        A string which is the content written to the dump file.

    Raises:
        IOError if fails to write to the dump file.
    """
    if os.path.isfile(lib_lsdump_path + '.gz'):
        with gzip.open(lib_lsdump_path + '.gz', 'rb') as f:
            lsdump_content = f.read()
    elif os.path.isfile(lib_lsdump_path):
        with open(lib_lsdump_path, 'rb') as f:
            lsdump_content = f.read()
    else:
        return ''

    vtable_dump = ParseVtablesFromLsdump(lsdump_content, abi_bitness)
    vtables = [vtable for vtable in vtable_dump.vtables
               if vtable.name in include_symbols]
    del vtable_dump.vtables[:]
    vtable_dump.vtables.extend(vtables)
    vtable_dump_text = text_format.MessageToString(vtable_dump)
    if vtable_dump_text:
        _CreateAndWrite(dump_path, vtable_dump_text)
    return vtable_dump_text

def ParseVtablesFromLsdump(abi_dump, abi_bitness):
    """Parses all vtables from a .lsdump abi-dump.

    Args:
        abi_dump: A lsdump output by header-abi-dumper/header-abi-linker.
        abi_bitness: A string describing the bitness of the target abi. The
                     value should be '32' or '64'.

    Returns:
        A vts.proto.VndkAbiDump_pb2.AbiDump() message.
    """
    VndkAbiDump = ExternalModules.VndkAbiDump
    AbiDump = ExternalModules.AbiDump

    tu = AbiDump.TranslationUnit()
    try:
        text_format.Merge(abi_dump, tu)
    except:
        print ('Warning: Cannot parse lsdump')
        return VndkAbiDump.AbiDump()

    assert(abi_bitness in ['32', '64'])
    offset_unit = {'32': 4, '64': 8}[abi_bitness]
    vtable_names = {e.name for e in tu.elf_objects if e.name.startswith('_ZTV')}

    # TODO: Not sure if UnusedFunctionPointer does anything or not
    vtable_function_kind = [
        AbiDump.VTableComponent.FunctionPointer,
        AbiDump.VTableComponent.CompleteDtorPointer,
        AbiDump.VTableComponent.DeletingDtorPointer,
        AbiDump.VTableComponent.UnusedFunctionPointer,
    ]

    vtable_dump = VndkAbiDump.AbiDump()
    for record_type in tu.record_types:
        name = record_type.tag_info.unique_id
        vtable_name = '_ZTV' + name[len('_ZTS'):]
        if vtable_name not in vtable_names:
            continue
        vtable = VndkAbiDump.VTable()
        vtable.name = vtable_name
        vtable.demangled_name = record_type.type_info.name
        for idx, vtable_component in enumerate(
                record_type.vtable_layout.vtable_components):
            offset = offset_unit * idx
            if vtable_component.kind not in vtable_function_kind:
                continue
            vtable_entry = vtable.vtable_entries.add()
            vtable_entry.offset = offset
            vtable_entry.name = vtable_component.mangled_component_name
            vtable_entry.demangled_name = ""
            vtable_entry.is_inlined = vtable_component.is_inlined
            vtable_entry.is_pure = vtable_component.is_pure
        if len(vtable.vtable_entries) > 0:
            vtable_dump.vtables.extend([vtable])
    return vtable_dump

def _LoadLibraryNamesFromTxt(vndk_lib_list_file):
    """Loads VNDK and VNDK-SP library names from a VNDK library list.

    Args:
        vndk_lib_list_file: A file object of
                            build/make/target/product/vndk/current.txt

    Returns:
        A list of strings, the VNDK and VNDK-SP library names with vndk/vndk-sp
        directory prefixes.
    """
    tags = (
        ("VNDK-core: ", len("VNDK-core: "), False),
        ("VNDK-SP: ", len("VNDK-SP: "), False),
        ("VNDK-private: ", len("VNDK-private: "), True),
        ("VNDK-SP-private: ", len("VNDK-SP-private: "), True),
    )
    lib_names = set()
    lib_names_exclude = set()
    for line in vndk_lib_list_file:
        for tag, tag_len, is_exclude in tags:
            if line.startswith(tag):
                lib_name = line[tag_len:].strip()
                if is_exclude:
                    lib_names_exclude.add(lib_name)
                else:
                    lib_names.add(lib_name)
    return sorted(lib_names - lib_names_exclude)


def _LoadLibraryNames(file_names):
    """Loads library names from files.

    Each element in the input list can be a .so file or a .txt file. The
    returned list consists of:
    - The .so file names in the input list.
    - The libraries tagged with VNDK-core or VNDK-SP in the .txt file.

    Args:
        file_names: A list of strings, the library or text file names.

    Returns:
        A list of strings, the library names (probably with vndk/vndk-sp
        directory prefixes).
    """
    lib_names = []
    for file_name in file_names:
        if file_name.endswith(".so"):
            lib_names.append(file_name)
        else:
            with open(file_name, "r") as txt_file:
                lib_names.extend(_LoadLibraryNamesFromTxt(txt_file))
    return lib_names


def _CollectLibraryPaths(root_dirs):
    """Collect all files under root directories and build a name-to-path dict.

    Args:
        root_dirs: The paths of root directories to be scanned.

    Returns:
        A dict that maps file names to file paths.
    """
    paths = {}
    for root_dir in root_dirs:
        for base_dir, dirnames, filenames in os.walk(root_dir):
            for filename in filenames:
                paths[filename] = os.path.join(base_dir, filename)
    return paths


def DumpAbi(output_dir, lib_names, lib_dir, vndk_version, object_dir,
            dumper_dir, lsdump_path):
    """Generates dump from libraries.

    Args:
        output_dir: The output directory of dump files.
        lib_names: The names of the libraries to dump.
        lib_dir: The path to the directory containing the libraries to dump.
        vndk_version: The VNDK version for shared libraries to dump.
        object_dir: The path to the directory containing intermediate objects.
        dumper_dir: The path to the directory containing the vtable dumper
                    executable and library.
        lsdump_path: The path to the directory containing lsdumps.

    Returns:
        A list of strings, the paths to the libraries not found in lib_dir.
    """
    ar_parser = ExternalModules.ar_parser
    static_symbols = set()
    for ar_name in ("libgcc", "libatomic", "libcompiler_rt-extras"):
        ar_path = os.path.join(
            object_dir, "STATIC_LIBRARIES", ar_name + "_intermediates",
            ar_name + ".a")
        static_symbols.update(ar_parser.ListGlobalSymbols(ar_path))

    lib_paths = _CollectLibraryPaths([
        os.path.join(lib_dir, "vndk-" + vndk_version),
        os.path.join(lib_dir, "vndk-sp-" + vndk_version)])

    missing_libs = []
    lib_bitness = os.path.basename(lib_dir)
    assert lib_bitness in ['lib', 'lib64'], (
           'Unexpected lib_dir: {} lib_dir should end with '
           '"lib" or "lib64"'.format(lib_dir))
    dump_dir = os.path.join(output_dir, lib_bitness)
    abi_bitness = {'lib': '32', 'lib64': '64'}[lib_bitness]
    for lib_name in lib_names:
        try:
            lib_path = lib_paths[lib_name]
        except KeyError:
            lib_path = os.path.join(lib_dir, "**", lib_name)
            print(lib_path)
            missing_libs.append(lib_path)
            print("Warning: Not found")
            print("")
            continue

        lib_pathname = os.path.relpath(lib_path, lib_dir)
        symbol_dump_path = os.path.join(dump_dir, lib_pathname + "_symbol.dump")
        vtable_dump_path = os.path.join(dump_dir, lib_pathname + "_vtable.dump")
        abi_dump_path = os.path.join(dump_dir, lib_pathname + ".abi.dump")
        lib_lsdump_path = os.path.join(lsdump_path, lib_name + '.lsdump')

        print(lib_path)
        if not os.path.isfile(lib_path):
            missing_libs.append(lib_path)
            print("Warning: Not found")
            print("")
            continue
        symbols = DumpSymbols(lib_path, symbol_dump_path, static_symbols)
        if symbols:
            print("Output: " + symbol_dump_path)
        else:
            print("No symbols")
        symbols = set(symbols)
        vtables = DumpVtables(
            lib_path, vtable_dump_path, dumper_dir, symbols)
        if vtables:
            print("Output: " + vtable_dump_path)
        else:
            print("No vtables")
        lsdump_vtables = DumpVtablesFromLsdump(
                lib_lsdump_path, abi_dump_path,  symbols, abi_bitness)
        if lsdump_vtables:
            print("Output: " + abi_dump_path)
        else:
            print("No lsdump vtables")
        if vtables and not lsdump_vtables:
            print ('Warning: lsdump_vtables empty but vtables not empty')
        print("")
    return missing_libs


def GetTargetArchDir(target_arch, target_arch_variant):
    if target_arch == target_arch_variant:
        return target_arch
    return '{}_{}'.format(target_arch, target_arch_variant)


def main():
    # Parse arguments
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("file", nargs="*",
                            help="the libraries to dump. Each file can be "
                                 ".so or .txt. The text file can be found at "
                                 "build/make/target/product/vndk/current.txt.")
    arg_parser.add_argument("--dumper-dir", "-d", action="store",
                            help="the path to the directory containing "
                                 "bin/vndk-vtable-dumper.")
    arg_parser.add_argument("--import-path", "-i", action="store",
                            help="the directory for VTS python modules. "
                                 "Default value is $ANDROID_BUILD_TOP/test")
    arg_parser.add_argument("--output", "-o", action="store",
                            help="output directory for ABI reference dump. "
                                 "Default value is PLATFORM_VNDK_VERSION.")
    args = arg_parser.parse_args()

    # Get target architectures
    build_top_dir = os.getenv("ANDROID_BUILD_TOP")
    if not build_top_dir:
        sys.exit("env var ANDROID_BUILD_TOP is not set")

    (binder_32_bit,
     vndk_version,
     target_is_64_bit,
     target_arch,
     target_arch_variant,
     target_2nd_arch,
     target_2nd_arch_variant) = GetBuildVariables(
        build_top_dir, abs_path=False, vars=(
            "BINDER32BIT",
            "PLATFORM_VNDK_VERSION",
            "TARGET_IS_64_BIT",
            "TARGET_ARCH",
            "TARGET_ARCH_VARIANT",
            "TARGET_2ND_ARCH",
            "TARGET_2ND_ARCH_VARIANT"))

    (target_lib_dir,
     target_obj_dir,
     target_2nd_lib_dir,
     target_2nd_obj_dir) = GetBuildVariables(
        build_top_dir, abs_path=True, vars=(
            "TARGET_OUT_SHARED_LIBRARIES",
            "TARGET_OUT_INTERMEDIATES",
            "2ND_TARGET_OUT_SHARED_LIBRARIES",
            "2ND_TARGET_OUT_INTERMEDIATES"))

    binder_bitness = '32' if binder_32_bit else '64'

    # Import elf_parser and vtable_parser
    ExternalModules.ImportParsers(build_top_dir)

    # Generate vtable dump from lsdump in TOP/prebuilts/abi-dumps
    lsdump_path_base = os.path.join(build_top_dir, 'prebuilts', 'abi-dumps',
                                    'vndk', vndk_version, binder_bitness)
    lsdump_path = os.path.join(lsdump_path_base,
            GetTargetArchDir(target_arch, target_arch_variant),
            'source-based')
    lsdump_path_2nd = os.path.join(lsdump_path_base,
            GetTargetArchDir(target_2nd_arch, target_2nd_arch_variant),
            'source-based')

    # Find vtable dumper
    if args.dumper_dir:
        dumper_dir = args.dumper_dir
    else:
        dumper_path = FindBinary(
            ExternalModules.vtable_parser.VtableParser.VNDK_VTABLE_DUMPER)
        dumper_dir = os.path.dirname(os.path.dirname(dumper_path))
    print("DUMPER_DIR=" + dumper_dir)

    output_dir = os.path.join((args.output if args.output else vndk_version),
                              ("binder32" if binder_32_bit else "binder64"),
                              target_arch)
    print("OUTPUT_DIR=" + output_dir)

    lib_names = _LoadLibraryNames(args.file)

    missing_libs = DumpAbi(output_dir, lib_names, target_lib_dir, vndk_version,
                           target_obj_dir, dumper_dir, lsdump_path)
    if target_2nd_arch:
        missing_libs += DumpAbi(output_dir, lib_names, target_2nd_lib_dir,
                                vndk_version, target_2nd_obj_dir, dumper_dir,
                                lsdump_path_2nd)

    if missing_libs:
        print("Warning: Could not find libraries:")
        for lib_path in missing_libs:
            print(lib_path)


if __name__ == "__main__":
    main()
