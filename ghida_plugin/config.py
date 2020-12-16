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

import idaapi
import json
import os
import sys
import tempfile

CONFIG_FILENAME = "ghida_config.json"
LP = "/home/osboxes/Desktop/ghidra_9.0.4"
WP = "C:\\Users\\IEUser\\Desktop\\ghidra_9.0.4"
GAAS = "http://localhost:8080/ghidra/api"


def _is_unix():
    return 'linux' in sys.platform or 'darwin' in sys.platform


class GhidaConfiguration(object):

    def __init__(self):
        self.__image_base = None
        self.__show_settings = True
        self.__global_settings = False
        self.__use_ghidra_server = False
        self.__disasm_tracker = True
        self.__load_save_cached_decompiled_code = False
        self.__load_save_cached_comments = False
        self.set_default_values()
        self.set_config_path()
        self.read_from_json()

    def set_default_values(self):
        """
        Set installation default values.
        """
        (plugin_path, _) = os.path.split(os.path.realpath(__file__))
        self.__ghidra_plugins_path = os.path.join(plugin_path, "ghidra_plugin")

        if _is_unix():
            self.__ghidra_install_path = LP
            self.__ghidra_headless_path = os.path.join(
                self.__ghidra_install_path,
                "support",
                "analyzeHeadless")
        else:
            self.__ghidra_install_path = WP
            self.__ghidra_headless_path = os.path.join(
                self.__ghidra_install_path,
                "support",
                "analyzeHeadless.bat")
        self.__ghidra_server_url = GAAS

    def set_config_path(self):
        """
        Set the JSON configuration file path.
        """
        # Get the path of the config file
        # plugins_path = idaapi.idadir(idaapi.PLG_SUBDIR)
        # ghida_plugin_path = os.path.join(
        #     plugins_path, "ghida_plugin", "config")
        # self.__config_path = os.path.join(ghida_plugin_path, CONFIG_FILENAME)

        self.__config_path = os.path.join(
            tempfile.gettempdir(), CONFIG_FILENAME)

    def read_from_json(self):
        """
        Read ghida configuration file.
        Avoid the user to always insert the information.
        """
        if not os.path.isfile(self.__config_path):
            # print("GhIDA:: [DEBUG] Configuration not found." +
            #       "Using default values.")
            return

        # Read configuration from the file
        with open(self.__config_path) as f_in:
            j_in = json.load(f_in)

            display_settings = j_in.get('SHOW_SETTINGS')
            if (display_settings is not None) and \
                    type(display_settings) == bool:
                self.__show_settings = display_settings

            ghidra_server = j_in.get('USE_GHIDRA_SERVER')
            if (ghidra_server is not None) and type(ghidra_server) == bool:
                self.__use_ghidra_server = ghidra_server

            if self.__use_ghidra_server:
                server_url = j_in.get('GHIDRA_SERVER_URL')
                if server_url is not None:
                    self.__ghidra_server_url = server_url

            else:
                installation_path = j_in.get('GHIDRA_INSTALLATION_PATH')
                if installation_path is not None:
                    self.__ghidra_install_path = installation_path
                    if _is_unix():
                        self.__ghidra_headless_path = os.path.join(
                            self.__ghidra_install_path,
                            "support",
                            "analyzeHeadless")
                    else:
                        self.__ghidra_headless_path = os.path.join(
                            self.__ghidra_install_path,
                            "support",
                            "analyzeHeadless.bat")

            cached_code = j_in.get('load_save_cached_code')
            if (cached_code is not None) and type(cached_code) == bool:
                self.__load_save_cached_decompiled_code = cached_code

            cached_comments = j_in.get('load_save_cached_comments')
            if (cached_comments is not None) and type(cached_comments) == bool:
                self.__load_save_cached_comments = cached_comments

        return

    def dump_to_json(self):
        """
        Save the GhIDA configuration file.
        """
        config = dict()
        config['SHOW_SETTINGS'] = self.__show_settings
        config['USE_GHIDRA_SERVER'] = self.__use_ghidra_server
        if self.__use_ghidra_server:
            config['GHIDRA_SERVER_URL'] = self.__ghidra_server_url
        else:
            config['GHIDRA_INSTALLATION_PATH'] = self.__ghidra_install_path

        config['load_save_cached_code'] = self.__load_save_cached_decompiled_code
        config['load_save_cached_comments'] = self.__load_save_cached_comments

        try:
            with open(self.__config_path, "w") as f_out:
                json.dump(config, f_out)
            print("GhIDA:: [INFO] Configuration saved to %s" %
                  self.__config_path)
        except Exception:
            print("GhIDA:: [!] Error while saving configuration to file")

    @property
    def show_settings(self):
        return self.__show_settings

    @show_settings.setter
    def show_settings(self, value):
        self.__show_settings = value

    @property
    def disasm_tracker(self):
        return self.__disasm_tracker

    @disasm_tracker.setter
    def disasm_tracker(self, value):
        self.__disasm_tracker = value

    @property
    def global_settings(self):
        return self.__global_settings

    @global_settings.setter
    def global_settings(self, value):
        self.__global_settings = value

    @property
    def use_ghidra_server(self):
        return self.__use_ghidra_server

    @use_ghidra_server.setter
    def use_ghidra_server(self, value):
        self.__use_ghidra_server = value

    @property
    def ghidra_server_url(self):
        return self.__ghidra_server_url

    @ghidra_server_url.setter
    def ghidra_server_url(self, value):
        self.__ghidra_server_url = value

    @property
    def ghidra_headless_path(self):
        return self.__ghidra_headless_path

    @property
    def ghidra_install_path(self):
        return self.__ghidra_install_path

    @ghidra_install_path.setter
    def ghidra_install_path(self, value):
        self.__ghidra_install_path = value
        if _is_unix():
            self.__ghidra_headless_path = os.path.join(
                self.__ghidra_install_path,
                "support",
                "analyzeHeadless")
        else:
            self.__ghidra_headless_path = os.path.join(
                self.__ghidra_install_path,
                "support",
                "analyzeHeadless.bat")

    @property
    def ghidra_plugins_path(self):
        return self.__ghidra_plugins_path

    @property
    def load_save_cached_code(self):
        return self.__load_save_cached_decompiled_code

    @load_save_cached_code.setter
    def load_save_cached_code(self, value):
        self.__load_save_cached_decompiled_code = value

    @property
    def load_save_cached_comments(self):
        return self.__load_save_cached_comments

    @load_save_cached_comments.setter
    def load_save_cached_comments(self, value):
        self.__load_save_cached_comments = value

    @property
    def image_base(self):
        return self.__image_base

    @image_base.setter
    def image_base(self, value):
        self.__image_base = value
