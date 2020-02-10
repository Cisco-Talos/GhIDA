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

import ida_kernwin
import idaapi

from .constants import COMMENT_FORM_TEXT
from .constants import RENAME_FORM_TEXT
from .constants import SETTINGS_FORM_TEXT

# from utility import get_address_for_symbol
from .utility import from_ghidra_to_ida_syntax_conversion
from .utility import from_ida_to_ghidra_syntax_conversion


USE_GHIDRAAAS_OPTION_CONST = 11
SAVE_CACHE_OPTION_CONST = 4
DO_NOT_SHOW_DIALOG_CONST = 7


# ------------------------------------------------------------
#   SYMBOLS HIGHLIGHTING
# ------------------------------------------------------------

def highlight_symbol_in_DISASM():
    """
    Select a symbol in the DECOMP view,
    highlight the corresponding symbols in IDA DISASM view.
    """
    # print("GhIDA:: [DEBUG] highlight_symbol_in_DISASM called")
    disasm_widget = idaapi.find_widget('IDA View-A')

    symbol = None
    ret = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
    if ret and ret[1]:
        symbol = ret[0]

    if not symbol:
        # TODO improve it
        # Highlight a non-existing symbole
        idaapi.set_highlight(disasm_widget, 'aaabbbccc', 1)
        return True

    converted_symbol = from_ghidra_to_ida_syntax_conversion(symbol)
    if converted_symbol:
        # Update IDA DISASM view
        idaapi.set_highlight(disasm_widget, converted_symbol, 1)
    else:
        # TODO improve it
        # Highlight a non-existing symbole
        idaapi.set_highlight(disasm_widget, 'aaabbbccc', 1)
    return True


def highlight_symbol_in_DECOMP():
    """
    Select a symbol in the IDA DISASM view,
    highlight the corresponding symbol in DECOMP view.
    """
    # print("GhIDA:: [DEBUG] highlight_symbol_in_DECOMP called")
    symbol = None
    ret = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
    if ret and ret[1]:
        symbol = ret[0]

    if not symbol:
        return

    converted_symbol = from_ida_to_ghidra_syntax_conversion(symbol)
    decompiler_widget = idaapi.find_widget('Decompiled Function')
    if converted_symbol:
        # Update IDA DECOMP view
        idaapi.set_highlight(decompiler_widget, converted_symbol, 1)
    else:
        idaapi.set_highlight(decompiler_widget, 'aaabbbccc', 1)
    return


# ------------------------------------------------------------
#   RENAME SYMBOLS FORM & utils
# ------------------------------------------------------------

class RenameForm(ida_kernwin.Form):

    def __init__(self, address, current_name):
        """
        Display a Pop-Up and get a new name for the symbol
        """
        self.invert = False
        rename_form_dict = {
            'cAddr': ida_kernwin.Form.NumericLabel(address,
                                                   ida_kernwin.Form.FT_ADDR),
            'cLbl': ida_kernwin.Form.StringLabel(current_name),
            'iStr': ida_kernwin.Form.StringInput(),
        }
        ida_kernwin.Form.__init__(self, RENAME_FORM_TEXT, rename_form_dict)


def display_rename_form(address, current_name):
    """
    Display the Pop-Up and return the new name
    """
    new_name = None
    f = RenameForm(address, current_name)
    f.Compile()
    if f.Execute() == 1:
        new_name = f.iStr.value
    f.Free()
    return new_name


# ------------------------------------------------------------
#   Add comment FORM
# ------------------------------------------------------------

class CommentForm(ida_kernwin.Form):

    def __init__(self, text):
        """
        Display a Pop-Up and get a new name for the symbol
        """
        self.invert = False
        comment_form_dict = {
            'iStr': ida_kernwin.Form.MultiLineTextControl(
                text=text,
                swidth=125,
                flags=ida_kernwin.Form.MultiLineTextControl.TXTF_FIXEDFONT)
        }
        ida_kernwin.Form.__init__(self,
                                  COMMENT_FORM_TEXT,
                                  comment_form_dict)


def display_comment_form(text):
    """
    Display the Pop-Up and return the new name
    """
    comment = None
    f = CommentForm(text)
    f.Compile()
    if f.Execute() == 1:
        comment = f.iStr.text
    f.Free()
    return comment


# ------------------------------------------------------------
#   SETTINGS FORM
# ------------------------------------------------------------

class GhIDASettingsForm(ida_kernwin.Form):

    def __init__(self):
        dd = {
            'FormChangeCall': ida_kernwin.Form.FormChangeCb(self.OnFormChange),
            'cGroup': ida_kernwin.Form.ChkGroupControl(("GLocal", "GRe")),
            'GhidraInstallationPath': ida_kernwin.Form.DirInput(),
            'GhidraaasURL': ida_kernwin.Form.StringInput(),
            'cGroup1': ida_kernwin.Form.ChkGroupControl(("GLocal1", "GRe1")),
            'cGroup2': ida_kernwin.Form.ChkGroupControl(("GLocal2", "GRe2"))
        }
        ida_kernwin.Form.__init__(self, SETTINGS_FORM_TEXT, dd)
        self.ghidraaas_selected = False
        self.save_cache = True
        self.show_dialog = True

    def OnFormChange(self, fid):
        if fid == -1:
            self.EnableField(self.GhidraInstallationPath, True)
            self.EnableField(self.GhidraaasURL, False)

        # USE GHIDRAAAS OPTION
        if fid == USE_GHIDRAAAS_OPTION_CONST:
            if self.ghidraaas_selected:
                self.EnableField(self.GhidraInstallationPath, True)
                self.EnableField(self.GhidraaasURL, False)
                self.ghidraaas_selected = False

            else:
                self.EnableField(self.GhidraInstallationPath, False)
                self.EnableField(self.GhidraaasURL, True)
                self.ghidraaas_selected = True

        # SAVE / LOAD CACHE
        if fid == SAVE_CACHE_OPTION_CONST:
            if self.save_cache:
                self.save_chache = False
            else:
                self.save_cache = True

        # DO NOT SHOW DIALOG
        if fid == DO_NOT_SHOW_DIALOG_CONST:
            if self.show_dialog:
                self.show_dialog = False
            else:
                self.show_dialog = True

        return 1
