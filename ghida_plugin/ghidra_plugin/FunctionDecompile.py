#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##############################################################################
#                                                                            #
#  FunctionDecompile - Ghidra plugin                                         #
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

import json
import sys

try:
    args = getScriptArgs()
    response_dict = dict()

    if len(args) < 2:
        print("usage: ./FunctionDecompile.py function_address output_path")
        sys.exit(0)

    decompInterface = ghidra.app.decompiler.DecompInterface()
    decompInterface.openProgram(currentProgram)

    # function_address mush be in hex format, with an optional ending 'L'
    address = int(args[0].rstrip("L"), 16)
    # output_path of the json file (should terminate with ".json")
    output_path = args[1]
    found = False

    response_dict['address'] = address

    functionIterator = currentProgram.getFunctionManager().getFunctions(True)
    for function in functionIterator:
        if function.getEntryPoint().getOffset() == address:
            decompileResults = decompInterface.decompileFunction(
                function, 30, monitor)
            if decompileResults.decompileCompleted():
                decompiledFunction = decompileResults.getDecompiledFunction()
                decompiled = decompiledFunction.getC()
                response_dict['status'] = "completed"
                response_dict['decompiled'] = decompiled
            else:
                response_dict['status'] = "error"
            found = True
            break

    if not found:
        response_dict['status'] = "error"

    with open(output_path, "w") as f_out:
        json.dump(response_dict, f_out)
    print("Json saved to %s" % output_path)

except Exception:
    response_dict['status'] = "error"
    print(json.dumps(response_dict))
