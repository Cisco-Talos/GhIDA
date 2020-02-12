#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##############################################################################
#                                                                            #
#  GhIDA: Ghidra decompiler for IDA Pro                                      #
#                                                                            #
#  Copyright 2019 Andrea Marcelli, Cisco Talos                               #
#                                                                            #
#  Licensed under the Apache License, Version 2.0 (the "License");           #
#  you may not use this file except in compliance with the License.          #
#  You may obtain a copy of the License at                                   #
#                                                                            #
#      http://www.apache.org/licenses/LICENSE-2.0                            #
#                                                                            #
#  Unless required by applicable law or agreed to in writing, software       #
#  distributed under the License is distributed on an "AS IS" BASIS,         #
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  #
#  See the License for the specific language governing permissions and       #
#  limitations under the License.                                            #
#                                                                            #
##############################################################################

import os
import re

import idaapi
import idc

from idaxml import SYMBLE_TABLE_DICT

PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__)))


# ------------------------------------------------------------
#   Renaming code
# ------------------------------------------------------------

def is_not_embedded_in_variable(target, line, var):
    """
    Implements an heuristic to decide if target should be
    renamed. Return true if the var is not embedded into
    a longer variable name.
    """
    check_1 = True
    check_2 = True

    # Check the char previous the match
    if line > 0:
        split = target[:line][-1]
        if split.isdigit() or split.isalpha() or split == '_':
            check_1 = False

    # Check the char after the match
    if len(target) > (line + len(var)):
        p = target[line + len(var):][0]
        if p.isdigit() or p.isalpha() or p == '_':
            check_2 = False

    return check_1 and check_2


def rename_variable_in_text(text, var, new):
    """
    Rename var into new in the text in input.
    Return the modified text.
    """
    new_text_list = list()
    for t in text.splitlines():
        cuts = [m.start() for m in re.finditer(var, t)]
        last = 0
        f = ""
        for c in cuts:
            if not is_not_embedded_in_variable(t, c, var):
                continue
            f += t[last:c]
            last = c + len(var)
            f += new

        f += t[last:]
        if f != t:
            new_text_list.append(f)
        else:
            new_text_list.append(t)
    new_text = "\n".join(new_text_list)
    return new_text


# ------------------------------------------------------------
#   GHIDRA vs. IDA syntax conversion
# ------------------------------------------------------------

def from_ghidra_to_ida_address_conversion(symbol):
    """
    Addresses are returned in integer format.
    """
    # Special case for function named FUN_ by Ghidra
    if re.match(r"FUN_[0-9a-fA-F]{1,16}", symbol):
        hex_addr = symbol.split("FUN_")[1]
        return int(hex_addr, 16)

    # Special case for data named DAT_ by Ghidra
    if re.match(r"DAT_[0-9a-fA-F]{1,16}", symbol):
        hex_addr = symbol.split("DAT_")[1]
        return int(hex_addr, 16)

    # Special case for data named _DAT_ by Ghidra
    if re.match(r"_DAT_[0-9a-fA-F]{1,16}", symbol):
        hex_addr = symbol.split("_DAT_")[1]
        return int(hex_addr, 16)

    return None


def from_ghidra_to_ida_syntax_conversion(symbol):
    """
    Convert a synbol from the Ghidra syntax to the IDA one
    """

    # Check if the word is in the symbol's dict
    address = get_address_for_symbol(symbol, strict=True)
    if address:
        # It already exists in IDA
        return symbol

    # Special case for symbols named FUN_ by Ghidra
    if re.match(r"FUN_[0-9a-fA-F]{1,16}", symbol):
        hex_addr = symbol.split("FUN_")[1].lstrip('0')
        symbol = "sub_" + hex_addr.upper()
        print("GhIDA:: [DEBUG] %s" % symbol)
        return symbol

    # Special case for symbols named DAT_ by Ghidra
    elif re.match(r"DAT_[0-9a-fA-F]{1,16}", symbol):
        hex_addr = symbol.split("DAT_")[1].lstrip('0')
        symbol = "unk_" + hex_addr.upper()
        print("GhIDA:: [DEBUG] %s" % symbol)
        return symbol

    # Special case for symbols named DAT_ by Ghidra
    elif re.match(r"_DAT_[0-9a-fA-F]{1,16}", symbol):
        hex_addr = symbol.split("_DAT_")[1].lstrip('0')
        symbol = "unk_" + hex_addr.upper()
        print("GhIDA:: [DEBUG] %s" % symbol)
        return symbol

    # Special case for hex values / addresses in Ghidra
    elif re.match(r"0x[0-9a-fA-F]{1,16}", symbol):
        hex_addr = symbol.replace('0x', '')
        symbol = hex_addr.upper() + 'h'
        print("GhIDA:: [DEBUG] %s" % symbol)
        return symbol

    return None


def from_ida_to_ghidra_syntax_conversion(symbol):
    """
    Convert a symbol from the IDA syntax to the Ghidra one.
    """
    # Check if the word is in the symbol's dict
    address = get_address_for_symbol(symbol, strict=True)
    if address:
        # It should exists in Ghidra too.
        return symbol

    # Special case for symbols named FUN_ by IDA
    if re.match(r"sub_[0-9a-fA-F]{1,16}", symbol):
        hex_addr = symbol.split("sub_")[1]
        if len(hex_addr) <= 8:
            hex_addr = '0' * (8 - len(hex_addr)) + hex_addr
        elif len(hex_addr) <= 16:
            hex_addr = '0' * (16 - len(hex_addr)) + hex_addr
        symbol = "FUN_" + hex_addr.lower()
        print("GhIDA:: [DEBUG] %s" % symbol)
        return symbol

    # Special case for symbols named DAT_ by IDA
    elif re.match(r"unk_[0-9a-fA-F]{1,16}", symbol):
        hex_addr = symbol.split("unk_")[1]
        if len(hex_addr) <= 8:
            hex_addr = '0' * (8 - len(hex_addr)) + hex_addr
        elif len(hex_addr) <= 16:
            hex_addr = '0' * (16 - len(hex_addr)) + hex_addr
        symbol = "DAT_" + hex_addr.lower()
        print("GhIDA:: [DEBUG] %s" % symbol)
        return symbol

    # Special case for hex values / addresses in IDA
    elif re.match(r"[0-9a-fA-F]{1,16}h", symbol):
        hex_addr = symbol.replace('h', '')
        symbol = '0x' + hex_addr.lower()
        print("GhIDA:: [DEBUG] %s" % symbol)
        return symbol

    return None


# ------------------------------------------------------------
#   SYMBOLS related functions
# ------------------------------------------------------------

# def get_address_for_symbol(symbol, symble_table_dict, strict=False):
def get_address_for_symbol(symbol, strict=False):
    """
    Return the address corresponding to the symbol in input.
    Use the SYMBLE_TABLE_DICT, and some basic heuristics.
    Addresses are in integer format.
    """
    if len(SYMBLE_TABLE_DICT) == 0:
        print("GhIDA:: [WARNING] SYMBLE_TABLE_DICT is empty")

    # Let's check in the symbol table
    if symbol in SYMBLE_TABLE_DICT:
        return SYMBLE_TABLE_DICT[symbol]

    # If Strict, do not apply heuristics to the name
    if strict:
        return None

    return from_ghidra_to_ida_address_conversion(symbol)


def updated_symbol_name_for_address(symbol_name, address, new_symbol_name):
    """
    Update the name of the symbol for a particular symbol.
    Useful when renaming a symbol.
    Addresses are in integer format.
    """
    if symbol_name in SYMBLE_TABLE_DICT:
        address = SYMBLE_TABLE_DICT[symbol_name]
        del SYMBLE_TABLE_DICT[symbol_name]
        SYMBLE_TABLE_DICT[new_symbol_name] = address
        print("GhIDA:: [DEBUG] updated symbol name in SYMBLE_TABLE_DICT")
    else:
        SYMBLE_TABLE_DICT[new_symbol_name] = address
        print("GhIDA:: [DEBUG] Created new symbol name in SYMBLE_TABLE_DICT")
    return


def check_if_symbol_is_used(symbol_name):
    """
    Return true if the symbol is already used
    """
    if symbol_name in SYMBLE_TABLE_DICT:
        return True
    return False

# ------------------------------------------------------------
#   Others
# ------------------------------------------------------------


def get_current_address():
    """
    Get the hex address of the function.
    """
    ca = idc.here()
    func = idaapi.get_func(ca)
    if not func:
        print("GhIDA:: [!] Error: function not found.")
        return None

    # Get function start address
    ea = func.start_ea
    ea = hex(ea).strip("0x").strip("L")
    return ea


def convert_address(ca):
    """
    Convert a decimal address into the hex address
    of the corresponding function.
    """
    func = idaapi.get_func(ca)
    if not func:
        print("GhIDA:: [!] Error: function not found.")
        return None

    # Get function start address
    ea = func.start_ea
    ea = hex(ea).strip("0x").strip("L")
    return ea


def plugin_resource(resource_name):
    """
    Return the full path for a given plugin resource file.
    """
    return os.path.join(
        PLUGIN_PATH,
        "ui",
        resource_name
    )
