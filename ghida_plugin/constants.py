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

COMMENT_FORM_TEXT = r"""
<Add a comment:{iStr}>
"""

RENAME_FORM_TEXT = r"""
Rename
Address:  {cAddr}
Symbol name: {cLbl}
<#Hint1#New name: {iStr}>
"""

SETTINGS_FORM_TEXT = r"""
GhIDA - Ghidra Decompiler for IDA Pro
{FormChangeCall}

Please, fill the configuration options.

< %40s {GhidraInstallationPath}>

<Use Ghidraaas server: {GRe}>{cGroup}>
< %40s {GhidraaasURL}>

<Save cache comments and code to file: {GRe2}>{cGroup2}>

<Do not show this dialog at startup: {GRe1}>{cGroup1}>

You can change the settings in Edit > Plugins > GhIDA Decompiler > Settings
""" % ("Ghidra installation path:", "Ghidraaas URL:")
