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

COMMENTS_CACHE_FILE = "comments_cache_%s.json"


class CommentsCache:

    def __init__(self, file_id=None, use_cache=False):
        self.__comments_cache = dict()
        self.set_cache_path(file_id)
        if use_cache:
            self.load_cache_from_json()

    def set_cache_path(self, file_id):
        try:
            if not file_id:
                file_id = "test"
            self.__cache_path = os.path.join(
                tempfile.gettempdir(), COMMENTS_CACHE_FILE % file_id)
            # print("GhIDA:: [DEBUG] comments_cache_path: %s" %
            #       self.__cache_path)

        except Exception:
            print("GhIDA:: [!] error while setting the comments cache")
            return

    def invalidate_cache(self):
        self.__comments_cache = dict()
        # print("GhIDA:: [DEBUG] comments cache is empty")
        return

    def add_comments_to_cache(self, address, comments_list):
        for c in comments_list:
            self.__comment_cache[address] = c
        # ll = len(comments_list)
        # print("GhIDA:: [DEBUG] addedd %d comments to cache (%s)" % ll)
        return

    def add_comment_to_cache(self, address, line_num, comment):
        if address not in self.__comments_cache:
            self.__comments_cache[address] = list()

        results = self.__comments_cache[address]
        for t in results:
            if t[0] == line_num:
                self.__comments_cache[address].remove(t)
        self.__comments_cache[address].append((line_num, comment))
        # print("GhIDA:: [DEBUG] addedd comments (%s, %d) to cache" %
        #       (address, line_num))
        # print("GhIDA:: [DEBUG] %d elements in cache" %
        #       len(self.__comments_cache))
        return

    def get_comments_cache(self, address):
        if address in self.__comments_cache:
            # print("GhIDA:: [DEBUG] comments cache hit (%s)" % address)
            return self.__comments_cache[address]
        # print("GhIDA:: [DEBUG] comments cache miss (%s)" % address)
        return None

    def dump_cache_to_json(self):
        try:
            with open(self.__cache_path, "w") as f_out:
                json.dump(self.__comments_cache, f_out)
        except Exception:
            print("GhIDA:: [!] Error while saving comments to file")

    def load_cache_from_json(self):
        try:
            # print("GhIDA:: [DEBUG] loading comments cache from json")
            with open(self.__cache_path) as f_in:
                self.__comments_cache = json.load(f_in)
                # print("GhIDA:: [DEBUG] loaded %d comments from cache" % len(
                #     self.__comments_cache))
        except Exception:
            print("GhIDA:: [!] error while loading comments from %s" %
                  self.__cache_path)
            self.__comments_cache = dict()
