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
import json
import os
import platform
import subprocess
import sys

from google.protobuf import message
from google.protobuf import text_format


class ExternalModules(object):
    """This class imports modules dynamically and keeps them as attributes.

    Assume the user runs this script in the source directory. The VTS modules
    are outside the search path and thus have to be imported dynamically.

    Attribtues:
        VndkAbiDump: The VndkAbiDump_pb2 module.
        AbiDump: The abi_dump_pb2 module.
        build_top_dir: The path to root directory of Android source.
    """

    @classmethod
    def ImportModules(cls, build_top_dir):
        """Imports proto modules.

        Args:
            build_top_dir: The path to root directory of Android source.
        """
        sys.path.append(os.path.join(build_top_dir, 'test'))
        sys.path.append(os.path.join(build_top_dir, 'test', 'vts-testcase'))
        sys.path.append(os.path.join(build_top_dir, 'development', 'vndk',
                                     'tools', 'header-checker'))
        cls.VndkAbiDump = importlib.import_module(
            "vndk.proto.VndkAbiDump_pb2")
        cls.AbiDump = importlib.import_module("proto.abi_dump_pb2")
        cls.build_top_dir = build_top_dir


class AttrDict(dict):
    """A dictionary with attribute accessors."""

    def __getattr__(self, key):
        """Returns self[key]."""
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)

    def __setattr__(self, key, value):
        """Assigns value to self[key]."""
        self[key] = value


class DumpAbiError(Exception):
    """The exception raised by DumpAbi."""
    pass


def _CreateAndWrite(path, data):
    """Creates directories on a file path and writes data to it.

    Args:
        path: The path to the file.
        data: The data to write.

    Raises:
        IOError if file operations fails.
    """
    dir_name = os.path.dirname(path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(dir_name)
    with open(path, "w") as f:
        f.write(data)


def _EncodeLsdump(msg):
    """Encode a text format abi_dump.TranslationUnit message to binary format.

    Args:
        msg: A string containing the text format message.

    Returns:
        A string containing the encoded result.

    Raises:
        DumpAbiError if encoding fails.
    """
    host_system_name = platform.system()
    if host_system_name == 'Linux':
        host_type = 'linux-x86_64'
    else:
        host_type = 'darwin-x86_64'
    cmd = [
        os.path.join(ExternalModules.build_top_dir, 'prebuilts', 'tools',
                     host_type, 'protoc', 'bin', 'protoc'),
        '-I/',
        '--encode=abi_dump.TranslationUnit',
        os.path.join(ExternalModules.build_top_dir, 'development', 'vndk',
                     'tools', 'header-checker', 'proto', 'abi_dump.proto'),
    ]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(msg)
    if proc.returncode:
        raise DumpAbiError(stderr)
    return stdout


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


def OpenTextOrGzipped(file_name):
    """Opens a file that is either in plaintext or gzipped format.

    If file_name ends with '.gz' then return gzip.open(file_name, 'rb'),
    else return open(file_name, 'rb').

    Args:
        file_name: The file name to open.

    Returns:
        A file object.
    """
    if file_name.endswith('.gz'):
        return gzip.open(file_name, 'rb')
    return open(file_name, 'rb')


def ReadLsdump(lsdump_path):
    """Returns a AbiDump_pb2.TranslationUnit() like object from file content.

    Args:
        lsdump_path: The path to the (gzipped) lsdump file.

    Returns:
        An AbiDump_pb2.TranslationUnit() object if lsdump_path contains protobuf
        text format message.
        An AttrDict() object if lsdump_path contains json format message.

    Raises:
        DumpAbiError if fails to open and read lsdump_path.
        DumpAbiError if fails to decode json or protobuf message.
    """
    AbiDump = ExternalModules.AbiDump

    if not os.path.isfile(lsdump_path):
        raise DumpAbiError('No such file: ' + lsdump_path)

    try:
        with OpenTextOrGzipped(lsdump_path) as f:
            lsdump_raw_bytes = f.read()
    except IOError as e:
        raise DumpAbiError(e)

    try:
        return json.loads(lsdump_raw_bytes, object_hook=AttrDict)
    except ValueError as e1:
        pass

    try:
        lsdump_binary = _EncodeLsdump(lsdump_raw_bytes)
        return AbiDump.TranslationUnit.FromString(lsdump_binary)
    except (DumpAbiError, message.DecodeError) as e2:
        pass

    raise DumpAbiError('Json: {}\nProtobuf: {}'.format(e1, e2))


def DumpAbiFromLsdump(lib_lsdump_path, dump_path, abi_bitness):
    """Dump abi from a lsdump to a dump file.

    The dump file is a vts.proto.VndkAbiDump_pb2.AbiDump() message.

    Args:
        lib_lsdump_path: The path to the (gzipped) lsdump file.
        dump_path: The path to the output text file.
        abi_bitness: A string describing the bitness of the target abi. The
                     value should be '32' or '64'.

    Returns:
        A string which is the content written to the dump file.

    Raises:
        DumpAbiError if fails to create the dump file.
    """
    VndkAbiDump = ExternalModules.VndkAbiDump

    tu = ReadLsdump(lib_lsdump_path)

    abi_dump = VndkAbiDump.AbiDump()

    ParseVtablesFromLsdump(abi_dump, tu, abi_bitness)
    ParseSymbolsFromLsdump(abi_dump, tu)

    abi_dump_text = text_format.MessageToString(abi_dump)
    try:
        _CreateAndWrite(dump_path, abi_dump_text)
    except IOError as e:
        raise DumpAbiError(e)

    return abi_dump_text


def ParseVtablesFromLsdump(abi_dump, tu, abi_bitness):
    """Parses vtables from a lsdump.

    Args:
        abi_dump: A VndkAbiDump_pb2.AbiDump() message to store the parsed
                  result to.
        tu: A abi_dump_pb2.TranslationUnit() message containing the content of
            lsdump.
        abi_bitness: A string describing the bitness of the target abi. The
                     value should be '32' or '64'.
    """
    VndkAbiDump = ExternalModules.VndkAbiDump
    AbiDump = ExternalModules.AbiDump

    assert(abi_bitness in ['32', '64'])
    offset_unit = {'32': 4, '64': 8}[abi_bitness]
    vtable_names = {e.name for e in tu.elf_objects if e.name.startswith('_ZTV')}
    function_name_demangle = {function.linker_set_key: function.function_name
                              for function in tu.functions}

    lsdump = AbiDump.VTableComponent
    vtable_function_kind = [
        lsdump.FunctionPointer,
        lsdump.CompleteDtorPointer,
        lsdump.DeletingDtorPointer,
        lsdump.UnusedFunctionPointer,
    ]
    vtable_entry_kind = {
        lsdump.VCallOffset: VndkAbiDump.VTableEntry.VCALLOFFSET,
        lsdump.VBaseOffset: VndkAbiDump.VTableEntry.VBASEOFFSET,
        lsdump.OffsetToTop: VndkAbiDump.VTableEntry.OFFSETTOTOP,
        lsdump.RTTI: VndkAbiDump.VTableEntry.RTTI,
        lsdump.FunctionPointer: VndkAbiDump.VTableEntry.VFUNCPOINTER,
        lsdump.CompleteDtorPointer: VndkAbiDump.VTableEntry.COMPLETEDTORPOINTER,
        lsdump.DeletingDtorPointer: VndkAbiDump.VTableEntry.DELETINGDTORPOINTER,
        lsdump.UnusedFunctionPointer: VndkAbiDump.VTableEntry.VFUNCPOINTER,
    }

    for record_type in tu.record_types:
        name = record_type.tag_info.unique_id
        vtable_name = '_ZTV' + name[len('_ZTS'):]
        if vtable_name not in vtable_names:
            continue
        vtable = abi_dump.vtables.add()
        vtable.name = vtable_name
        vtable.demangled_name = record_type.type_info.name
        for idx, vtable_component in enumerate(
                record_type.vtable_layout.vtable_components):
            if vtable_component.kind not in vtable_entry_kind:
                print('Warning: Unexpected vtable_component kind\n{}'
                      .format(vtable_component))
                continue
            vtable_entry = vtable.vtable_entries.add()
            vtable_entry.offset = idx * offset_unit
            vtable_entry.kind = vtable_entry_kind[vtable_component.kind]
            if vtable_component.kind in vtable_function_kind:
                vtable_entry.name = vtable_component.mangled_component_name
                if vtable_entry.name in function_name_demangle:
                    vtable_entry.demangled_name = (
                        function_name_demangle[vtable_entry.name])
                if vtable_component.is_pure:
                    vtable_entry.is_pure = True
            elif vtable_component.kind == lsdump.RTTI:
                vtable_entry.name = vtable_component.mangled_component_name
    # Sort by name so we get stable results.
    abi_dump.vtables.sort(key=lambda x: x.name)


def ParseSymbolsFromLsdump(abi_dump, tu):
    """Parses symbols from a lsdump.

    Args:
        abi_dump: A VndkAbiDump_pb2.AbiDump() message to store the parsed
                  result to.
        tu: A abi_dump_pb2.TranslationUnit() message containing the content of
            lsdump.
    """
    VndkAbiDump = ExternalModules.VndkAbiDump
    AbiDump = ExternalModules.AbiDump

    global_vars = {global_var.linker_set_key for global_var in tu.global_vars}
    functions = {function.linker_set_key for function in tu.functions}
    elf_objects = {elf_object.name for elf_object in tu.elf_objects}
    elf_functions = {elf_function.name for elf_function in tu.elf_functions}

    symbol_binding = {
        AbiDump.Global: VndkAbiDump.Symbol.GLOBAL,
        AbiDump.Weak: VndkAbiDump.Symbol.WEAK,
    }
    binding = {elf_object.name: symbol_binding[elf_object.binding]
               for elf_object in tu.elf_objects}

    binding.update({elf_function.name: symbol_binding[elf_function.binding]
                    for elf_function in tu.elf_functions})

    def CollectInterestingSymbols():
        """Yields compiler generated symbols that defines part of the ABI.

        _ZTV, _ZTT: Virtual table & VTT.
        _ZTI, _ZTS: Typeinfo structure & typeinfo name.
        _ZTh, _ZTv, _ZTc: Thunk symbols.
        """
        record_names = {record_type.tag_info.unique_id[len('_ZTS'):]
                        for record_type in tu.record_types}
        # Collect _ZT[VTIS] symbols whose base record type is in lsdump.
        for e in elf_objects - global_vars:
            if e[:len('_ZTV')] in {'_ZTV', '_ZTT', 'ZTI', 'ZTS'}:
                if e[len('_ZTV'):] in record_names:
                    yield e
        # Collect _ZT[hvc] symbols whose target function is exported by lsdump.
        for e in elf_functions - functions:
            nominal_target = _FindThunkBase(e)
            if nominal_target and nominal_target in functions:
                yield e

    symbols = global_vars | functions | set(CollectInterestingSymbols())
    abi_dump.symbols.extend(
        VndkAbiDump.Symbol(name=symbol, binding=binding[symbol])
        for symbol in symbols
    )
    # Sort by name so we get stable results.
    abi_dump.symbols.sort(key=lambda x: x.name)


def _FindThunkBase(name):
    """Finds thunk symbol's base function.

    <thunk-symbol> ::= _ZT <call-offset> <base-encoding>
                     | _ZTc <call-offset> <call-offset> <base-encoding>
    <call-offset>  ::= h <nv-offset>
                     | v <v-offset>
    <nv-offset>    ::= <offset-number> _
    <v-offset>     ::= <offset-number> _ <offset-number> _

    Args:
        name: A string, the symbol name to resolve.

    Returns:
        A string, symbol name of the nominal target function (base function).
        None if name is not a thunk symbol.
    """
    def ConsumeOffset(tok, beg=0):
        """Consumes a <offset-number>."""
        pos = tok.find('_', beg) + 1
        return tok[:pos], tok[pos:]

    def ConsumeCallOffset(tok):
        """Consumes a <call-offset>."""
        if tok[:1] == 'h':
            lhs, rhs = ConsumeOffset(tok, 1)
        elif tok[:1] == 'v':
            lhs, rhs = ConsumeOffset(tok, 1)
            lhs2, rhs = ConsumeOffset(rhs)
            if lhs and lhs2:
                lhs = lhs + lhs2
            else:
                lhs, rhs = '', tok
        else:
            lhs, rhs = '', tok
        return lhs, rhs

    if name.startswith('_ZTh') or name.startswith('_ZTv'):
        lhs, rhs = ConsumeCallOffset(name[len('_ZT'):])
        if lhs:
            return '_Z' + rhs
    if name.startswith('_ZTc'):
        lhs, rhs = ConsumeCallOffset(name[len('_ZTc'):])
        lhs2, rhs = ConsumeCallOffset(rhs)
        if lhs and lhs2:
            return '_Z' + rhs
    return None


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


def DumpAbi(output_dir, lib_names, lsdump_path, abi_bitness):
    """Generates ABI dumps from library lsdumps.

    Args:
        output_dir: The output directory of dump files.
        lib_names: The names of the libraries to dump.
        lsdump_path: The path to the directory containing lsdumps.
        abi_bitness: A string describing the bitness of the target abi.
                     The value should be '32' or '64'.

    Returns:
        A list of strings, the libraries whose ABI dump fails to be created.
    """
    missing_dumps = []
    for lib_name in lib_names:
        dump_path = os.path.join(output_dir, lib_name + '.abi.dump')
        lib_lsdump_path = os.path.join(lsdump_path, lib_name + '.lsdump')
        if os.path.isfile(lib_lsdump_path + '.gz'):
            lib_lsdump_path += '.gz'

        print(lib_lsdump_path)
        try:
            DumpAbiFromLsdump(lib_lsdump_path, dump_path, abi_bitness)
        except DumpAbiError as e:
            missing_dumps.append(lib_name)
            print(e)
        else:
            print('Output: ' + dump_path)
        print('')
    return missing_dumps


def _GetTargetArchDir(target_arch, target_arch_variant):
    if target_arch == target_arch_variant:
        return target_arch
    return '{}_{}'.format(target_arch, target_arch_variant)


def _GetAbiBitnessFromArch(target_arch):
    arch_bitness = {
        'arm': '32',
        'arm64': '64',
        'x86': '32',
        'x86_64': '64',
    }
    return arch_bitness[target_arch]


def main():
    # Parse arguments
    description = (
        'Generates VTS VNDK ABI test abidumps from lsdump. '
        'Option values are read from build variables if no value is given. '
        'If none of the options are specified, then abidumps for target second '
        'arch are also generated.'
    )
    arg_parser = argparse.ArgumentParser(description=description)
    arg_parser.add_argument("file", nargs="*",
                            help="the libraries to dump. Each file can be "
                                 ".so or .txt. The text file can be found at "
                                 "build/make/target/product/vndk/current.txt.")
    arg_parser.add_argument("--output", "-o", action="store",
                            help="output directory for ABI reference dump. "
                                 "Default value is PLATFORM_VNDK_VERSION.")
    arg_parser.add_argument('--platform-vndk-version',
                            help='platform VNDK version. '
                                 'Default value is PLATFORM_VNDK_VERSION.')
    arg_parser.add_argument('--binder-bitness',
                            choices=['32', '64'],
                            help='bitness of binder interface. '
                                 'Default value is 32 if BINDER32BIT is set '
                                 'else is 64.')
    arg_parser.add_argument('--target-main-arch',
                            choices=['arm', 'arm64', 'x86', 'x86_64'],
                            help='main CPU arch of the device. '
                                 'Default value is TARGET_ARCH.')
    arg_parser.add_argument('--target-arch',
                            choices=['arm', 'arm64', 'x86', 'x86_64'],
                            help='CPU arch of the libraries to dump. '
                                 'Default value is TARGET_ARCH.')
    arg_parser.add_argument('--target-arch-variant',
                            help='CPU arch variant of the libraries to dump. '
                                 'Default value is TARGET_ARCH_VARIANT.')

    args = arg_parser.parse_args()

    build_top_dir = os.getenv("ANDROID_BUILD_TOP")
    if not build_top_dir:
        sys.exit("env var ANDROID_BUILD_TOP is not set")

    # If some options are not specified, read build variables as default values.
    if not all([args.platform_vndk_version,
                args.binder_bitness,
                args.target_main_arch,
                args.target_arch,
                args.target_arch_variant]):
        [platform_vndk_version,
         binder_32_bit,
         target_arch,
         target_arch_variant,
         target_2nd_arch,
         target_2nd_arch_variant] = GetBuildVariables(
            build_top_dir,
            False,
            ['PLATFORM_VNDK_VERSION',
             'BINDER32BIT',
             'TARGET_ARCH',
             'TARGET_ARCH_VARIANT',
             'TARGET_2ND_ARCH',
             'TARGET_2ND_ARCH_VARIANT']
        )
        target_main_arch = target_arch
        binder_bitness = '32' if binder_32_bit else '64'

    if args.platform_vndk_version:
        platform_vndk_version = args.platform_vndk_version

    if args.binder_bitness:
        binder_bitness = args.binder_bitness

    if args.target_main_arch:
        target_main_arch = args.target_main_arch

    if args.target_arch:
        target_arch = args.target_arch

    if args.target_arch_variant:
        target_arch_variant = args.target_arch_variant

    dump_targets = [(platform_vndk_version,
                     binder_bitness,
                     target_main_arch,
                     target_arch,
                     target_arch_variant)]

    # If all options are not specified, then also create dump for 2nd arch.
    if not any([args.platform_vndk_version,
                args.binder_bitness,
                args.target_main_arch,
                args.target_arch,
                args.target_arch_variant]):
        dump_targets.append((platform_vndk_version,
                             binder_bitness,
                             target_main_arch,
                             target_2nd_arch,
                             target_2nd_arch_variant))

    # Import proto modules
    ExternalModules.ImportModules(build_top_dir)

    for target_tuple in dump_targets:
        (platform_vndk_version,
         binder_bitness,
         target_main_arch,
         target_arch,
         target_arch_variant) = target_tuple

        # Determine abi_bitness from target architecture
        abi_bitness = _GetAbiBitnessFromArch(target_arch)

        # Generate ABI dump from lsdump in TOP/prebuilts/abi-dumps
        lsdump_path = os.path.join(
            build_top_dir,
            'prebuilts',
            'abi-dumps',
            'vndk',
            platform_vndk_version,
            binder_bitness,
            _GetTargetArchDir(target_arch, target_arch_variant),
            'source-based')
        if not os.path.exists(lsdump_path):
            print('Warning: lsdump path does not exist: ' + lsdump_path)
            print('No abidump created.')
            continue

        output_dir = os.path.join(
            args.output if args.output else platform_vndk_version,
            'binder' + binder_bitness,
            target_main_arch,
            'lib64' if abi_bitness == '64' else 'lib')
        print("OUTPUT_DIR=" + output_dir)

        lib_names = _LoadLibraryNames(args.file)

        missing_dumps = DumpAbi(output_dir, lib_names, lsdump_path, abi_bitness)

        if missing_dumps:
            print('Warning: Fails to create ABI dumps for libraries:')
            for lib_name in missing_dumps:
                print(lib_name)


if __name__ == "__main__":
    main()
