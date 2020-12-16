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

import tempfile
import json
import os


CODE_CACHE_FILE = "decompiled_cache_%s.json"


class DecompiledCache:

    def __init__(self, file_id=None, use_cache=False):
        self.__decompiled_cache = dict()
        self.set_cache_path(file_id)
        if use_cache:
            self.load_cache_from_json()
        return

    def set_cache_path(self, file_id):
        try:
            if not file_id:
                file_id = "test"
            self.__cache_path = os.path.join(
                tempfile.gettempdir(), CODE_CACHE_FILE % file_id)
            # print("GhIDA:: [DEBUG] code_cache_path: %s" % self.__cache_path)

        except Exception:
            print("GhIDA:: [!] error while setting the comments cache")
            return

    def invalidate_cache(self, address=None):
        if not address:
            self.__decompiled_cache = dict()
            # print("GhIDA:: [DEBUG] decompile cache is empty")
        else:
            if address in self.__decompiled_cache:
                del self.__decompiled_cache[address]
                # print("GhIDA:: [DEBUG] removed item (%s) from cache" % address)
            else:
                # print("GhIDA:: [DEBUG] item (%s) not found" % address)
                pass
        return

    def add_decompiled_to_cache(self, address, code):
        self.__decompiled_cache[address] = code
        # print("GhIDA:: [DEBUG] addedd code to cache (%s)" % address)
        # print("GhIDA:: [DEBUG] %d elements in cache" %
        #       len(self.__decompiled_cache))
        return

    def update_decompiled_cache(self, address, code):
        if address in self.__decompiled_cache:
            self.__decompiled_cache[address] = code
            # print("GhIDA:: [DEBUG] cache updated (%s)" % address)
        return

    def get_decompiled_cache(self, address):
        if address in self.__decompiled_cache:
            # print("GhIDA:: [DEBUG] decompiled cache hit (%s)" % address)
            return self.__decompiled_cache[address]
        # print("GhIDA:: [DEBUG] decompiled cache miss (%s)" % address)
        return None

    def dump_cache_to_json(self):
        try:
            with open(self.__cache_path, "w") as f_out:
                json.dump(self.__decompiled_cache, f_out)
        except Exception:
            print("GhIDA:: [!] Error while saving code to file")

    def load_cache_from_json(self):
        try:
            # print("GhIDA:: [DEBUG] loading decomp cache from json")
            with open(self.__cache_path) as f_in:
                self.__decompiled_cache = json.load(f_in)
                # print("GhIDA:: [DEBUG] loaded %d items from cache" % len(
                #     self.__decompiled_cache))
        except Exception:
            print("GhIDA:: [!] error while loading code from %s" %
                  self.__cache_path)
            self.__decompiled_cache = dict()
