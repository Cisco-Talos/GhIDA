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

try:
    from pygments.lexers import CLexer
    from pygments.token import Token
except Exception:
    # Missing library is managed at the plugin entry
    pass


import ida_kernwin
import idaapi
import idautils
import idc

import ghida_plugin as gl

DECOMP_VIEW = None
GHIDA_CONF = None
DECOMPILED_CACHE = None
COMMENTS_CACHE = None


# ------------------------------------------------------------
#   IDA MENU - HANDLERS
# ------------------------------------------------------------


class ShowSettingsHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):
        display_configuration_form()
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class ShowDecompWindowHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):
        if DECOMP_VIEW:
            DECOMP_VIEW.Show()
        else:
            print("GhIDA:: [DEBUG] DECOMP_VIEW non existing")
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ------------------------------------------------------------
#   DECOMPILED VIEW -- POP-UP HANDLERS
# ------------------------------------------------------------

class GoToCustViewerHandler(idaapi.action_handler_t):

    def __init__(self, view):
        idaapi.action_handler_t.__init__(self)
        self.view = view

    # Say hello when invoked.
    def activate(self, ctx):
        print("GhIDA:: [DEBUG] GoToCustViewerHandler HELLO")
        goto()
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class AddCommentCustViewerHandler(idaapi.action_handler_t):

    def __init__(self, view):
        idaapi.action_handler_t.__init__(self)
        self.view = view

    # Say hello when invoked.
    def activate(self, ctx):
        print("GhIDA:: [DEBUG] AddCommentCustViewerHandler HELLO")
        DECOMP_VIEW.add_comment()
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class RenameCustViewerHandler(idaapi.action_handler_t):

    def __init__(self, view):
        idaapi.action_handler_t.__init__(self)
        self.view = view

    # Say hello when invoked.
    def activate(self, ctx):
        print("GhIDA:: [DEBUG] RenameCustViewerHandler HELLO")
        DECOMP_VIEW.rename_symbol()
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ------------------------------------------------------------
#   ScreenEAHook
# ------------------------------------------------------------

class ScreenEAHook(ida_kernwin.View_Hooks):

    def __init__(self):
        ida_kernwin.View_Hooks.__init__(self)
        print("GhIDA [DEBUG] ScreenEAHook initialized")

    def view_loc_changed(self, widget, curloc, prevloc):
        """
        view_loc_changed is called each time the user clicks
        somwhere. This is used to synchronize the IDA DISASM
        view with the IDA DECOM view. The synchronization is
        active only when the decompile view has been created
        and the synch option has been selected in the pop-up
        menu.
        """
        # Check if the selected address has changed
        # if curloc.plce.toea() != prevloc.plce.toea():
        #     return

        # Hooking the IDA DISASM view only
        if idaapi.get_widget_type(widget) != idaapi.BWN_DISASM:
            return

        # If the DECOMP view has already been created.
        if DECOMP_VIEW:
            # Get the new address
            ca = curloc.plce.toea()
            ea = gl.convert_address(ca)

            # This is a valid function address
            if ea:
                # The synch is active
                if GHIDA_CONF.disasm_tracker:
                    # The address in DECOMP view is different
                    if ea != DECOMP_VIEW.ea:
                        # Update DECOMP view
                        DECOMP_VIEW.switch_to_address(ea)

                # Update the selection
                return gl.highlight_symbol_in_DECOMP()

            # This is not a valid function address
            if not ea:
                # If the synch is active
                if GHIDA_CONF.disasm_tracker:
                    DECOMP_VIEW.clear(msg="[!] Function not found.",
                                      do_show=False)
        return


# ------------------------------------------------------------
#   GOTO utils
# ------------------------------------------------------------

def goto(shift=False):
    print("GhIDA:: [DEBUG] goto called")

    symbol = None
    ret = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
    if ret and ret[1]:
        symbol = ret[0]

    if not symbol:
        return False

    address = gl.get_address_for_symbol(symbol)
    if not address:
        return False

    print("OnDblClick, shift=%d, selection:%s, address:%s" %
          (shift, symbol, address))

    # Update IDA DISASM view
    idaapi.jumpto(address)

    # Update IDA DECOMP view
    ea = gl.convert_address(address)
    print("GhIDA:: [DEBUG] update view to %s" % ea)
    DECOMP_VIEW.switch_to_address(ea)

    return True


# ------------------------------------------------------------
#   SIMPLECUSTVIEWER FOR THE DECOMPILED RESULT
# ------------------------------------------------------------

# Check this example: https://github.com/nologic/idaref/blob/master/idaref.py
class DecompiledViewer_t(idaapi.simplecustviewer_t):

    def color_line(self, line):
        """
        """
        lexer = CLexer()
        tokens = list(lexer.get_tokens(line))
        new_line = ""
        for t in tokens:
            ttype = t[0]
            ttext = str(t[1])
            if ttype == Token.Text:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_INSN)

            elif ttype == Token.Text.Whitespace:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_INSN)

            elif ttype == Token.Error:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_ERROR)

            elif ttype == Token.Other:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_DSTR)

            elif ttype == Token.Keyword:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_KEYWORD)

            elif ttype == Token.Name:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_LIBNAME)

            elif ttype == Token.Literal:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_LOCNAME)

            elif ttype == Token.Literal.String:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_STRING)

            elif ttype == Token.Literal.Number:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_DNUM)

            elif ttype == Token.Operator:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_ALTOP)

            elif ttype == Token.Punctuation:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_SYMBOL)

            elif ttype == Token.Comment:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_REGCMT)

            elif ttype == Token.Comment.Single:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_REGCMT)

            elif ttype == Token.Generic:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_CREFTAIL)

            else:
                new_line += idaapi.COLSTR(ttext, idaapi.SCOLOR_CREFTAIL)
        return new_line

    def add_colored_text(self, text):
        """
        Parse the code with the C lexer and display the colored text
        in the decompiled view.
        """
        for line in text.splitlines():
            new_line = self.color_line(line)
            self.AddLine(new_line)
        return

    def Create(self, decompiled, ea):
        """
        Create a new view with the decompiled code
        """
        title = "Decompiled Function"
        self.__ea = ea
        self.__decompiled = decompiled

        # Create the customviewer
        if not idaapi.simplecustviewer_t.Create(self, title):
            return False

        # for line in decompiled.splitlines():
        #     self.AddLine(str(line))
        self.add_colored_text(decompiled)

        return True

    def clear(self, msg=None, do_show=True):
        """
        Clear the view content
        """
        self.ClearLines()
        self.__ea = None
        self.__decompiled = None
        if msg:
            for line in msg.splitlines():
                self.AddLine(line)
        self.Refresh()
        if do_show:
            self.Show()
        return

    def update(self, ea, decompiled, do_show=True):
        """
        Update the content of the view with the new decompiled code
        """
        self.__ea = ea
        self.__decompiled = decompiled
        self.ClearLines()
        self.add_colored_text(decompiled)
        self.Refresh()
        if do_show:
            self.Show()

        # Update the cache
        DECOMPILED_CACHE.update_decompiled_cache(ea, decompiled)
        print("GhIDA:: [DEBUG] GhIDA DECOM view updated to %s" % ea)
        return

    def switch_to_address(self, ea):
        """
        The IDA DIASM view switched to a new address, change
        the decompiled view accordingly.
        """
        self.__ea = ea
        decompile_function_wrapper(cache_only=True, do_show=False)
        return

    def add_comment(self):
        """
        Add a commment to the selected line
        """
        print("GhIDA:: [DEBUG] add_comment called")
        colored_line = self.GetCurrentLine(notags=1)
        if not colored_line:
            idaapi.warning("Select a line")
            return False

        # Use pygments to parse the line to check if there are comments
        line = idaapi.tag_remove(colored_line)
        lexer = CLexer()
        tokens = list(lexer.get_tokens(line))
        text = ""
        text_comment = ""
        for t in tokens:
            ttype = t[0]
            ttext = str(t[1])
            if ttype == Token.Comment.Single:
                text_comment = ttext.replace('//', '').strip()
            else:
                text += ttext

        # Get the new comment
        comment = gl.display_comment_form(text_comment)
        if not comment or len(comment) == 0:
            return False
        comment = comment.replace("//", "").replace("\n", " ")
        comment = comment.strip()

        # Create the new text
        full_comment = "\t// %s" % comment
        text = text.rstrip()
        new_text = text + full_comment
        text_colored = self.color_line(new_text)

        num_line = self.GetLineNo()
        self.EditLine(num_line, text_colored)
        self.RefreshCurrent()

        # Add comment to cache
        COMMENTS_CACHE.add_comment_to_cache(self.__ea, num_line, full_comment)

        print("GhIDA:: [DEBUG] Added comment to #line: %d (%s)" %
              (num_line, new_text))
        return

    def add_comments(self, comment_list):
        """
        Updated the view with the available comments
        """
        for item in comment_list:
            lineno = item[0]
            comment = item[1]
            if len(comment) == 0:
                continue
            line = self.GetLine(lineno)
            if not line:
                print("GhIDA:: [!] line not found")
                continue
            line_text = line[0]
            if not line_text:
                print("GhIDA:: [!] line-text not found")
                continue
            line_text = idaapi.tag_remove(line_text) + comment
            new_line = self.color_line(line_text)
            self.EditLine(lineno, new_line)

        self.Refresh()
        print("GhIDA:: [DEBUG] updated comments terminated")
        return

    def rename_symbol(self):
        """
        Rename the symbol "symbol" with the new name
        provided by the user in the Pop-Up
        """
        # Get the symbol
        symbol = None
        ret = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
        if ret and ret[1]:
            symbol = ret[0]

        if not symbol:
            idaapi.warning("Select a symbol")
            return False

        # Get the address
        address = gl.get_address_for_symbol(symbol)
        if not address:
            print("GhIDA:: [!] Symbol %s not found" % symbol)
            return False

        # Display a Pop-up to get the new name
        new_name = gl.display_rename_form(address, symbol)
        if not new_name or len(new_name) == 0:
            return

        # Check for white_spaces in the new symbol name
        for letter in new_name:
            if not (letter.isdigit() or letter.isalpha() or letter == '_'):
                print("GhIDA:: [!] symbol name contains invalid char")
                return

        # Check if new_name is already used
        if gl.check_if_symbol_is_used(new_name):
            print("GhIDA:: [!] symble name already used")
            return

        # Update symbol name in SYMBLE DICT:
        gl.updated_symbol_name_for_address(symbol, address, new_name)

        # Update symbol name in IDA DISASM view.
        print("GhIDA:: [DEBUG] New symbol name: %s" % new_name)

        # Update symbol name in the decompiled view
        new_code = gl.rename_variable_in_text(
            self.__decompiled,
            symbol,
            new_name)
        self.update(self.__ea, new_code)

        # Add comments
        comment_list = COMMENTS_CACHE.get_comments_cache(self.__ea)
        if comment_list:
            self.add_comments(comment_list)

        print("GhIDA:: [INFO] Symbol name updated in IDA DECOMP view.")

        if idc.set_name(address, new_name):
            # Refresh the view
            idaapi.request_refresh(idaapi.IWID_DISASMS)
            # Highlight the new identifier
            gl.highlight_symbol_in_DISASM()
            print("GhIDA:: [INFO] Symbol name updated in IDA DISASM view.")
            return

        print("GhIDA:: [!] IDA DISASM rename error")
        return

    def OnClick(self, shift):
        """
        User clicked in the view
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        return gl.highlight_symbol_in_DISASM()

    def OnDblClick(self, shift):
        """
        User dbl-clicked in the view
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        return goto(shift)

    def OnKeydown(self, vkey, shift):
        """
        User pressed a key
        @param vkey: Virtual key code
        @param shift: Shift flag
        @return: Boolean. True if you handled the event
        """
        # print("OnKeydown, vk=%d shift=%d" % (vkey, shift))

        # # Esc --> close the window
        if vkey == 27:
            # TODO.. go back in the history, as disasm does
            return True

        # N or n --> rename a symbol
        if vkey == ord('N'):
            self.rename_symbol()

        # : --> add a comment
        elif vkey == 186 and shift == 1:
            self.add_comment()

        else:
            return False

        return True

    @property
    def ea(self):
        return self.__ea


# ------------------------------------------------------------
#   HANDLERS FOR THE POP-UP MENU IN DISASMS VIEW
# ------------------------------------------------------------

class InvalidateCache(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):
        print("GhIDA:: [DEBUG] InvalidateCache HELLO")
        address = gl.get_current_address()
        if not address:
            print("GhIDA:: [DEBUG] address not found")
            return

        DECOMPILED_CACHE.invalidate_cache(address)
        gl.force_export_XML_file()

        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class DisasmTracker(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):
        print("GhIDA:: [DEBUG] DisasmTracker HELLO")

        if GHIDA_CONF.disasm_tracker:
            GHIDA_CONF.disasm_tracker = False
            print("GhIDA:: [INFO] synchronization disabled")

            # Update the description in the pop-up menu.
            ida_kernwin.update_action_label(
                "my:disasmtracker", "Enable decompile view synchronization")

        else:
            GHIDA_CONF.disasm_tracker = True
            print("GhIDA:: [INFO] synchronization activated")

            # Update the description in the pop-up menu.
            ida_kernwin.update_action_label(
                "my:disasmtracker", "Disable decompile view synchronization")

            # Update the DECOMP view to the current address
            ea = gl.get_current_address()
            if ea:
                DECOMP_VIEW.switch_to_address(ea)
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class DisasmsHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Say hello when invoked.
    def activate(self, ctx):
        print("GhIDA:: [DEBUG] DisasmsHandler HELLO")
        decompile_function_wrapper()
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class DisasmsHooks(idaapi.UI_Hooks):

    def finish_populating_tform_popup(self, form, popup):
        # TODO - Attach to the functions view.
        # if idaapi.get_tform_type(form) == idaapi.BWN_FUNCS:
        #     idaapi.attach_action_to_popup(
        #         form, popup, "my:disasmsaction", None)

        # Attach to the disassembler view only
        if idaapi.get_tform_type(form) == idaapi.BWN_DISASMS:
            idaapi.attach_action_to_popup(
                form, popup, "my:disasmsaction", None)
            idaapi.attach_action_to_popup(
                form, popup, "my:disasmtracker", None)
            idaapi.attach_action_to_popup(
                form, popup, "my:invalidatecache", None)


def register_handlers():
    """
    Register the handlers for the pop-up menu to interact with the UI
    """
    print("GhIDA:: [DEBUG] Registering handlers")

    # Load a custom icon
    icon_path = gl.plugin_resource("ghida.png")
    icon_data = str(open(icon_path, "rb").read())
    icon_ghida = idaapi.load_custom_icon(data=icon_data)

    idaapi.register_action(idaapi.action_desc_t(
        "my:disasmsaction",
        "Decompile function with GhIDA",
        DisasmsHandler(),
        None,
        'IDA plugin for Ghidra decompiler',
        icon_ghida))

    disasmtracker_action = idaapi.action_desc_t(
        "my:disasmtracker",
        "Disable decompile view synchronization",
        DisasmTracker(),
        None,
        None,
        icon_ghida)
    idaapi.register_action(disasmtracker_action)

    idaapi.register_action(idaapi.action_desc_t(
        "my:invalidatecache",
        "Clear cache for current function",
        InvalidateCache(),
        None,
        None,
        icon_ghida))

    # Add the settings item in the menu
    show_settings_action = idaapi.action_desc_t(
        'my:showsettingsaction',
        'GhIDA Settings',
        ShowSettingsHandler(),
        None,
        'GhIDA Settings',
        icon_ghida)
    idaapi.register_action(show_settings_action)

    idaapi.attach_action_to_menu(
        'Edit/Settings/GhIDA Settings',
        'my:showsettingsaction',
        idaapi.SETMENU_APP)

    # Add the view decompile window in the menu
    show_decomp_window_action = idaapi.action_desc_t(
        'my:showdecompilewindowaction',
        'GhIDA decomp view',
        ShowDecompWindowHandler(),
        None,
        'GhIDA decomp view',
        icon_ghida)
    idaapi.register_action(show_decomp_window_action)

    idaapi.attach_action_to_menu(
        'View/Open subviews/GhIDA',
        'my:showdecompilewindowaction',
        idaapi.SETMENU_APP)

    return


# ------------------------------------------------------------
#   DEFINING GLOBAL VARS AND GHIDA INITIAL CONFIGURATION
# ------------------------------------------------------------

def load_configuration():
    """
    """
    global GHIDA_CONF
    global DECOMPILED_CACHE
    global COMMENTS_CACHE

    # Loading the plugin configuration
    print("GhIDA:: [DEBUG] Reading GhIDA configuration")
    GHIDA_CONF = gl.GhidaConfiguration()

    print("GHIDA_CONF.load_save_cached_code",
          GHIDA_CONF.load_save_cached_code)
    print("GHIDA_CONF.load_save_cached_comments",
          GHIDA_CONF.load_save_cached_comments)

    md5 = idautils.GetInputFileMD5()

    # Initalize the cache (and load cached objects)
    DECOMPILED_CACHE = gl.DecompiledCache(
        file_id=md5,
        use_cache=GHIDA_CONF.load_save_cached_code)
    COMMENTS_CACHE = gl.CommentsCache(
        file_id=md5,
        use_cache=GHIDA_CONF.load_save_cached_comments)

    return

# ------------------------------------------------------------
#   HANDLERS FOR THE POP-UP MENU IN DECOMP VIEW
# ------------------------------------------------------------


def register_actions_and_handlers_decompile_view():
    """
    Attach the following actions in the pop-up menu of the
    decompiled view.
    """
    # Load a custom icon
    icon_path = gl.plugin_resource("ghida.png")
    icon_data = str(open(icon_path, "rb").read())
    icon_ghida = idaapi.load_custom_icon(data=icon_data)

    decompiler_widget = idaapi.find_widget('Decompiled Function')
    # TODO alternative
    # decompiler_widget = idaapi.get_current_tform()

    # Add Rename to the pop-up
    action_renamecustviewer = idaapi.action_desc_t(
        'my:renamecustviewerhandler',
        'Rename',
        RenameCustViewerHandler(
            DECOMP_VIEW),
        None,
        None,
        icon_ghida)
    decompiler_widget = idaapi.find_widget('Decompiled Function')
    idaapi.register_action(action_renamecustviewer)
    idaapi.attach_action_to_popup(decompiler_widget,
                                  None,
                                  "my:renamecustviewerhandler",
                                  None)

    # Add add-comment to the pop-up
    action_addcommentcustviewer = idaapi.action_desc_t(
        'my:addcommentcustviewer',
        'Add comment',
        AddCommentCustViewerHandler(
            DECOMP_VIEW),
        None,
        None,
        icon_ghida)
    idaapi.register_action(action_addcommentcustviewer)
    idaapi.attach_action_to_popup(decompiler_widget,
                                  None,
                                  "my:addcommentcustviewer",
                                  None)

    # Add goto to the pop-up
    action_gotocustviewerhandler = idaapi.action_desc_t(
        'my:gotocustviewerhandler',
        'Goto',
        GoToCustViewerHandler(
            DECOMP_VIEW),
        None,
        None,
        icon_ghida)
    idaapi.register_action(action_gotocustviewerhandler)
    idaapi.attach_action_to_popup(decompiler_widget,
                                  None,
                                  "my:gotocustviewerhandler",
                                  None)
    return


# ------------------------------------------------------------
#   GHIDA Configuration FORM
# ------------------------------------------------------------

def display_configuration_form():
    """
    Display a configuration dialog for the user.
    """
    f = gl.GhIDASettingsForm()
    f.Compile()
    f.GhidraInstallationPath.value = GHIDA_CONF.ghidra_install_path
    f.GhidraaasURL.value = GHIDA_CONF.ghidra_server_url
    r = f.Execute()

    if r == 1:  # OK
        # Do not display the settings menu anymore
        GHIDA_CONF.global_settings = True

        if f.cGroup.value == 0:
            # Use local Ghidra
            GHIDA_CONF.use_ghidra_server = False
            GHIDA_CONF.ghidra_install_path = f.GhidraInstallationPath.value
        else:
            # Use Ghidra server (Ghidraaas)
            GHIDA_CONF.use_ghidra_server = True
            GHIDA_CONF.ghidra_server_url = f.GhidraaasURL.value

        if f.cGroup1.value == 0:
            # Do not display the popup at startup
            GHIDA_CONF.show_settings = True
        else:
            # Dispaly the menu at startup
            GHIDA_CONF.show_settings = False

        if f.cGroup2.value == 0:
            # Do not save cache to file
            GHIDA_CONF.load_save_cached_code = False
            GHIDA_CONF.load_save_cached_comments = False
        else:
            # Save cache to file
            GHIDA_CONF.load_save_cached_code = True
            GHIDA_CONF.load_save_cached_comments = True

        print("GHIDA_CONF.global_settings", GHIDA_CONF.global_settings)
        print("GHIDA_CONF.use_ghidra_server", GHIDA_CONF.use_ghidra_server)
        print("GHIDA_CONF.ghidra_install_path", GHIDA_CONF.ghidra_install_path)
        print("GHIDA_CONF.ghidra_server_url", GHIDA_CONF.ghidra_server_url)
        print("GHIDA_CONF.show_settings", GHIDA_CONF.show_settings)
        print("GHIDA_CONF.load_save_cached_code",
              GHIDA_CONF.load_save_cached_code)
        print("GHIDA_CONF.load_save_cached_comments",
              GHIDA_CONF.load_save_cached_comments)

        # Save configuration to file
        GHIDA_CONF.dump_to_json()
        return True

    # Canceled
    return False


# ------------------------------------------------------------
#   DECOMPILE FUNCTION - CORE
# ------------------------------------------------------------

def decompile_function_wrapper(cache_only=False, do_show=True):
    """
    Perform all the operations to decompile the code of the selected
    function and display in the decompile view.
    """
    try:
        global DECOMP_VIEW
        ea = gl.get_current_address()
        if not ea:
            # This is not a function
            # GhIDA can decompile only IDA recognized functions.
            return

        # Set the base_image
        image_base = idaapi.get_imagebase()
        if GHIDA_CONF.image_base is None:
            GHIDA_CONF.image_base = image_base

        # Check if the program has been rebased
        if GHIDA_CONF.image_base != image_base:
            print(
                "GhIDA:: [DEBUG] program has been rebased. Invalidating caches.")
            DECOMPILED_CACHE.invalidate_cache()
            COMMENTS_CACHE.invalidate_cache()
            gl.force_export_XML_file()

        # Display the Configuration form
        if GHIDA_CONF.show_settings and \
                not GHIDA_CONF.global_settings:
            canceled = not(display_configuration_form())
            if canceled:
                return

        # If exists, clear the decompile view.
        if DECOMP_VIEW:
            DECOMP_VIEW.clear(msg="Decompiling function...",
                              do_show=do_show)

        # Call export XML file. It also populates the SYMBOL DICT TABLE (S_D_T)
        # for the highlighting, renaming, etc.
        # Do it here because I need S_D_T it also if the result is in the
        # cache.
        gl.export_ida_project_to_xml()

        # Check the cache
        decompiled = DECOMPILED_CACHE.get_decompiled_cache(ea)

        # Cache miss - opt1: do not use Ghidra, just display what is in the
        # cache
        if not decompiled and cache_only:
            # This is a redundant check...
            if DECOMP_VIEW:
                msg = "Function 0x%s\n\n" % ea
                msg += "Decompiled code not available in cache.\n"
                msg += "Press Ctrl-Alt-D or Right click GhIDA decompiler "
                msg += "to decompile the function."
                DECOMP_VIEW.clear(msg=msg, do_show=do_show)
            print("GhIDA:: [DEBUG] Function code not available in cache.")
            return

        # Cache miss - opt2: Use Ghidra to decompile the function
        if not decompiled:
            decompiled = gl.decompile_function(
                address=ea,
                use_ghidra_server=GHIDA_CONF.use_ghidra_server,
                ghidra_headless_path=GHIDA_CONF.ghidra_headless_path,
                ghidra_plugins_path=GHIDA_CONF.ghidra_plugins_path,
                ghidra_server_url=GHIDA_CONF.ghidra_server_url)

            if decompiled:
                # Add decompiled_code to cache
                DECOMPILED_CACHE.add_decompiled_to_cache(ea, decompiled)
            else:
                # Something went wrong or was interrupted
                if DECOMP_VIEW:
                    DECOMP_VIEW.clear(msg="Decompiling interrupted.",
                                      do_show=do_show)
                print("GhIDA:: [!] Decompilation interrupted.")
                return

        # Decompiled code is available.
        if DECOMP_VIEW:
            # The view exists, update it
            DECOMP_VIEW.update(ea, decompiled, do_show=do_show)
        else:
            # Create the view
            DECOMP_VIEW = DecompiledViewer_t()
            if not DECOMP_VIEW.Create(decompiled, ea):
                print("GhIDA:: [!] Error creating the view")
                return
            DECOMP_VIEW.Show()

        register_actions_and_handlers_decompile_view()

        # Add comments
        comment_list = COMMENTS_CACHE.get_comments_cache(ea)
        if comment_list:
            DECOMP_VIEW.add_comments(comment_list)

        return
    except Exception:
        print("GhIDA:: [!] Decompilation wrapper error")
        idaapi.warning("GhIDA decompilation wrapper error")


# ------------------------------------------------------------
#   GHIDRA DECOMPILER PLUGIN
# ------------------------------------------------------------

class GhIDADecompiler_t(idaapi.plugin_t):
    comment = "GhIDA Decompiler for IDA Pro"
    help = "GhIDA Decompiler shortcut key is Ctrl-Alt-D"
    wanted_name = "GhIDA Decompiler"
    wanted_hotkey = "Ctrl-Alt-D"
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        # Print header
        print("=" * 60)
        print("GhIDA Decompiler v{0}".format(gl.ghida_vv))
        print("Andrea Marcelli <anmarcel@cisco.com>")
        print("Cisco Talos, June 2019")
        print("GhIDA Decompiler shortcut key is Ctrl-Alt-D")
        print("=" * 60)

        self.__uihooks = None
        self.__seh = None

        try:
            import pygments
        except Exception:
            print("GhIDA:: [!] pygments library is missing")
            print("pip2 install pygments")
            return idaapi.PLUGIN_SKIP

        try:
            import requests
        except Exception:
            print("GhIDA:: [!] requests library is missing")
            print("pip2 install requests")
            return idaapi.PLUGIN_SKIP

        load_configuration()
        register_handlers()

        # Avoid displaying Running python script dialog
        # Otherwise, it breaks the UI and Cancel button
        idaapi.disable_script_timeout()

        # Hooking
        self.__uihooks = DisasmsHooks()
        self.__uihooks.hook()

        self.__seh = ScreenEAHook()
        self.__seh.hook()
        return idaapi.PLUGIN_KEEP

    def term(self):
        # Unhook
        if self.__uihooks:
            self.__uihooks.unhook()
        if self.__seh:
            self.__seh.unhook()

        # Remove temporary files
        gl.ghida_finalize(GHIDA_CONF.use_ghidra_server,
                          GHIDA_CONF.ghidra_server_url)

        # Dump the cache to file
        if GHIDA_CONF.load_save_cached_code:
            DECOMPILED_CACHE.dump_cache_to_json()
        if GHIDA_CONF.load_save_cached_comments:
            COMMENTS_CACHE.dump_cache_to_json()

    def run(self, arg):
        # Decompile the function
        decompile_function_wrapper()


def PLUGIN_ENTRY():
    # Check IDA version
    if not gl.is_ida_version_supported:
        return

    return GhIDADecompiler_t()
