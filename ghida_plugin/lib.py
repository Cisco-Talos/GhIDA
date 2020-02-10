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

import json
import os
import signal
import sys
import tempfile
import time

import queue as Queue
import random
import requests
import string
import subprocess
import threading

import ida_auto
import ida_kernwin
import idaapi
import idautils
import idc

from .idaxml import Cancelled
from .idaxml import XmlExporter

# This value can be changed
TIMEOUT = 300

# Do not modify it
COUNTER_MAX = TIMEOUT * 10
# Do not modify it
SLEEP_LENGTH = 0.1
GLOBAL_CHECKIN = False
GLOBAL_FILENAME = None
EXPORT_XML_FILE = True

# ------------------------------------------------------------
#   PLUGIN CORE FUNCTIONS
# ------------------------------------------------------------


def force_export_XML_file():
    global EXPORT_XML_FILE
    EXPORT_XML_FILE = True
    return


def create_random_filename():
    global GLOBAL_FILENAME

    if not GLOBAL_FILENAME:
        letters = [random.choice(string.ascii_letters) for i in range(5)]
        random_string = ''.join(letters)
        GLOBAL_FILENAME = "%s_%s" % (
            idautils.GetInputFileMD5().hex(), random_string)
    return GLOBAL_FILENAME


def terminate_process(pid):
    """
    Kill the process
    """
    if os.name == 'posix':
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    else:
        os.kill(pid, -9)
    return


def get_ida_exported_files():
    """
    Return the path of the XML and bytes files.
    """
    create_random_filename()
    dirname = os.path.dirname(idc.get_idb_path())
    file_path = os.path.join(dirname, GLOBAL_FILENAME)
    xml_file_path = file_path + ".xml"
    bin_file_path = file_path + ".bytes"

    return xml_file_path, bin_file_path


def export_ida_project_to_xml():
    """
    Export the current project into XML format
    """
    global EXPORT_XML_FILE

    xml_file_path, bin_file_path = get_ida_exported_files()
    print("GhIDA:: [DEBUG] EXPORT_XML_FILE: %s" % EXPORT_XML_FILE)

    # Check if files are alredy available
    if os.path.isfile(xml_file_path) and \
            os.path.isfile(bin_file_path) and \
            not EXPORT_XML_FILE:
        return xml_file_path, bin_file_path

    EXPORT_XML_FILE = False

    # Otherwise call the XML exporter IDA plugin
    print("GhIDA:: [DEBUG] Exporting IDA project into XML format")
    st = idc.set_ida_state(idc.IDA_STATUS_WORK)
    xml = XmlExporter(1)

    try:
        xml.export_xml(xml_file_path)
        print("GhIDA:: [INFO] XML exporting completed")
    except Cancelled:
        ida_kernwin.hide_wait_box()
        msg = "GhIDA:: [!] XML Export cancelled!"
        print("\n" + msg)
        idc.warning(msg)
    except Exception:
        ida_kernwin.hide_wait_box()
        msg = "GhIDA:: [!] Exception occurred: XML Exporter failed!"
        print(msg)
        excinfo = sys.exc_info()
        print(excinfo)
        idc.warning(msg)
    finally:
        xml.cleanup()
        ida_auto.set_ida_state(st)

    # check if both xml and binary format exist
    if not os.path.isfile(xml_file_path) or \
            not os.path.isfile(bin_file_path):
        raise Exception("GhIDA:: [!] XML or bytes file non existing.")
    return xml_file_path, bin_file_path


def remove_temporary_files():
    """
    Remove XML and bytes temporary files.
    """
    try:
        xml_file_path, bin_file_path = get_ida_exported_files()
        if os.path.isfile(xml_file_path):
            os.remove(xml_file_path)

        if os.path.isfile(bin_file_path):
            os.remove(bin_file_path)

    except Exception:
        print("GhIDA:: [!] Unexpected error while removing temporary files.")


# ------------------------------------------------------------
#   PLUGIN UTILITY FUNCTIONS
# ------------------------------------------------------------

def is_ida_version_supported():
    """
    Check which IDA version is supported
    """
    major, minor = map(int, idaapi.get_kernel_version().split("."))
    if major >= 7:
        return True
    print("GhIDA:: [!] IDA Pro 7.xx supported only")
    return False


def ghida_finalize(use_ghidra_server, ghidra_server_url):
    """
    Remove temporary files and
    checkout from Ghidraaas server.
    """
    try:
        remove_temporary_files()

        if use_ghidra_server:
            ghidraaas_checkout(ghidra_server_url)

    except Exception:
        print("GhIDA:: [!] Finalization error")
        idaapi.warning("GhIDA finalization error")


# ------------------------------------------------------------
#   GHIDRA LOCAL
# ------------------------------------------------------------

def ghidra_headless(address,
                    xml_file_path,
                    bin_file_path,
                    ghidra_headless_path,
                    ghidra_plugins_path):
    """
    Call Ghidra in headless mode and run the plugin
    FunctionDecompile.py to decompile the code of the function.
    """
    try:
        if not os.path.isfile(ghidra_headless_path):
            print("GhIDA:: [!] ghidra analyzeHeadless not found.")
            raise Exception("analyzeHeadless not found")

        decompiled_code = None
        idaapi.show_wait_box("Ghida decompilation started")

        prefix = "%s_" % address
        output_temp = tempfile.NamedTemporaryFile(prefix=prefix, delete=False)
        output_path = output_temp.name
        # print("GhIDA:: [DEBUG] output_path: %s" % output_path)
        output_temp.close()

        cmd = [ghidra_headless_path,
               ".",
               "Temp",
               "-import",
               xml_file_path,
               '-readOnly',
               '-scriptPath',
               ghidra_plugins_path,
               '-postScript',
               'FunctionDecompile.py',
               address,
               output_path,
               "-noanalysis",
               "-deleteProject"]

        # Options to 'safely' terminate the process
        if os.name == 'posix':
            kwargs = {
                'preexec_fn': os.setsid
            }
        else:
            kwargs = {
                'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP,
                'shell': True
            }

        p = subprocess.Popen(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             **kwargs)

        stop = False
        counter = 0
        print("GhIDA:: [INFO] Ghidra headless (timeout: %ds)" % TIMEOUT)
        print("GhIDA:: [INFO] Waiting Ghidra headless analysis to finish...")

        while not stop:
            time.sleep(SLEEP_LENGTH)
            counter += 1
            subprocess.Popen.poll(p)

            # Process terminated
            if p.returncode is not None:
                print("GhIDA:: [DEBUG] ", str(p.stdout.read(), 'utf-8'))
                stop = True
                print("GhIDA:: [INFO] Ghidra analysis completed!")
                continue

            # User terminated action
            if idaapi.user_cancelled():
                # Termiante the process!
                terminate_process(p.pid)
                stop = True
                print("GhIDA:: [!] Ghidra analysis interrupted.")
                continue

            # Process timeout
            if counter > COUNTER_MAX:
                terminate_process(p.pid)
                stop = True
                print("GhIDA:: [!] Decompilation error - timeout reached")
                continue

        # Check if JSON response is available
        if os.path.isfile(output_path):
            with open(output_path) as f_in:
                j = json.load(f_in)
                if j['status'] == "completed":
                    decompiled_code = j['decompiled']
                else:
                    print("GhIDA:: [!] Decompilation error -",
                          " JSON response is malformed")

            # Remove the temporary JSON response file
            os.remove(output_path)
        else:
            print("GhIDA:: [!] Decompilation error - JSON response not found")
            idaapi.warning("Ghidra headless decompilation error")

    except Exception as e:
        print("GhIDA:: [!] %s" % e)
        print("GhIDA:: [!] Ghidra headless analysis failed")
        idaapi.warning("Ghidra headless analysis failed")
        decompiled_code = None

    finally:
        idaapi.hide_wait_box()
        return decompiled_code


# ------------------------------------------------------------
#   GHIDRAAAS - GHIDRA SERVER
# ------------------------------------------------------------

def ghidraaas_checkin_thread(bin_file_path,
                             filename,
                             ghidra_server_url,
                             md5_hash,
                             queue):
    """
    ghidraaas_checkin - inner thread
    """
    try:
        options = {
            "md5": md5_hash,
            "filename": filename,
        }

        bb = [
            ('bytes',
                (bin_file_path, open(bin_file_path, 'rb'),
                 'application/octet')),
            ('data',
                ('data', json.dumps(options),
                    'application/json'))
        ]

        r = requests.post("%s/ida_plugin_checkin/" %
                          ghidra_server_url, files=bb, timeout=TIMEOUT)

        print("GhIDA:: [DEBUG] Check-in status code: %d" % r.status_code)
        if r.status_code == 200:
            print("GhIDA:: [INFO] Check-in completed")
            queue.put(True)
            return

        else:
            print("GhIDA:: [!] Check-in error: %s (%s)" % (r.reason, r.text))
            queue.put(False)
            return

    except Exception as e:
        print("GhIDA:: [!] %s" % e)
        print("GhIDA:: [!] Check-in error (thread)." +
              " Please check Ghidraaas address.")
        queue.put(False)
        return


def ghidraaas_checkin(bin_file_path, filename, ghidra_server_url):
    """
    Upload the .bytes files in ghidraaas.
    One time only (until IDA is restarted...)
    """
    idaapi.show_wait_box("Connecting to Ghidraaas. Sending bytes file...")
    try:
        md5_hash = idautils.GetInputFileMD5().hex()
        queue = Queue.Queue()

        my_args = (bin_file_path, filename, ghidra_server_url, md5_hash, queue)
        t1 = threading.Thread(target=ghidraaas_checkin_thread,
                              args=my_args)
        t1.start()

        counter = 0
        stop = False

        while not stop:
            time.sleep(SLEEP_LENGTH)
            counter += 1

            # User terminated action
            if idaapi.user_cancelled():
                stop = True
                print("GhIDA:: [!] Check-in interrupted.")
                continue

            # Reached TIIMEOUT
            if counter > COUNTER_MAX:
                stop = True
                print("GhIDA:: [!] Timeout reached.")
                continue

            # Thread terminated
            if not t1.isAlive():
                stop = True
                print("GhIDA:: [DEBUG] Thread terminated.")
                continue

        print("GhIDA:: [DEBUG] Joining check-in thread.")
        t1.join(0)
        q_result = queue.get_nowait()
        print("GhIDA:: [DEBUG] Thread joined. Got queue result.")
        idaapi.hide_wait_box()
        return q_result

    except Exception:
        idaapi.hide_wait_box()
        print("GhIDA:: [!] Check-in error.")
        idaapi.warning("GhIDA check-in error")
        return False


def ghidraaas_checkout_thread(md5_hash, ghidra_server_url):
    """
    ghidraaas_checkout - inner thread
    """
    try:
        data = {
            "md5": md5_hash,
            "filename": GLOBAL_FILENAME,
        }

        r = requests.post("%s/ida_plugin_checkout/" %
                          ghidra_server_url,
                          json=json.dumps(data),
                          timeout=TIMEOUT)

        print("GhIDA:: [DEBUG] Check-out status code: %d" % r.status_code)
        if r.status_code != 200:
            print("GhIDA:: [!] Check-out error: %s (%s)" % (r.reason, r.text))

    except Exception as e:
        print("GhIDA:: [!] %s" % e)
        print("GhIDA:: [!] Check-out error (thread)")


def ghidraaas_checkout(ghidra_server_url):
    """
    That's all. Remove .bytes file from Ghidraaas server.
    """
    if not GLOBAL_CHECKIN:
        return

    idaapi.show_wait_box(
        "Connecting to Ghidraaas. Removing temporary files...")
    try:
        md5_hash = idautils.GetInputFileMD5().hex()
        aargs = (md5_hash, ghidra_server_url)

        t1 = threading.Thread(target=ghidraaas_checkout_thread,
                              args=aargs)
        t1.start()

        counter = 0
        stop = False

        while not stop:
            time.sleep(SLEEP_LENGTH)
            counter += 1

            if idaapi.user_cancelled():
                print("GhIDA:: [!] Check-out interrupted.")
                stop = True
                continue

            if counter > COUNTER_MAX:
                print("GhIDA:: [!] Timeout reached.")
                stop = True
                continue

            if not t1.isAlive():
                stop = True
                print("GhIDA:: [DEBUG] Thread terminated.")
                continue

        print("GhIDA:: [DEBUG] Joining check-out thread.")
        t1.join(0)
        print("GhIDA:: [DEBUG] Thread joined")
        idaapi.hide_wait_box()
        return

    except Exception:
        idaapi.hide_wait_box()
        print("GhIDA:: [!] Check-out error")
        idaapi.warning("GhIDA check-out error")
        return


def ghidraaas_decompile_thread(address,
                               xml_file_path,
                               bin_file_path,
                               ghidra_server_url,
                               filename,
                               md5_hash,
                               queue):
    """
    Connect to Ghidraaas to decompile a funciton -- inner thread
    """
    try:
        options = {
            "md5": md5_hash,
            "filename": filename,
            "address": address
        }

        bb = [
            ('xml',
                (xml_file_path, open(xml_file_path, 'rb'),
                    'application/octet')),
            ('data',
                ('data', json.dumps(options),
                    'application/json'))
        ]

        r = requests.post("%s/ida_plugin_get_decompiled_function/" %
                          ghidra_server_url, files=bb, timeout=TIMEOUT)

        print("GhIDA:: [DEBUG] Decompilation status code: %d" % r.status_code)

        if r.status_code == 200:
            print("GhIDA:: [INFO] Decompilation completed")
            j = r.json()
            if j['status'] == "completed":
                queue.put(j['decompiled'])
                return

            print("GhIDA:: [!] Unknown decompilation error")
            queue.put(None)
            return

        else:
            print("GhIDA:: [!] Decompilation error: %s (%s)" %
                  (r.reason, r.text))
            queue.put(None)
            return

    except Exception as e:
        print("GhIDA:: [!] %s" % e)
        print("GhIDA:: [!] Decompilation error (thread)")
        queue.put(None)


def ghidraaas_decompile(address,
                        xml_file_path,
                        bin_file_path,
                        ghidra_server_url):
    """
    Send the xml file to ghidraaas
    and ask to decompile a function
    """
    global GLOBAL_CHECKIN

    # Filename without the .xml extension
    filename = GLOBAL_FILENAME

    if not GLOBAL_CHECKIN:
        if ghidraaas_checkin(bin_file_path, filename, ghidra_server_url):
            GLOBAL_CHECKIN = True
        else:
            raise Exception("[!] Ghidraaas Check-in error")

    idaapi.show_wait_box(
        "Connecting to Ghidraaas. Decompiling function %s" % address)

    try:
        md5_hash = idautils.GetInputFileMD5().hex()
        queue = Queue.Queue()

        aargs = (address, xml_file_path, bin_file_path,
                 ghidra_server_url, filename, md5_hash, queue)
        t1 = threading.Thread(target=ghidraaas_decompile_thread,
                              args=aargs)
        t1.start()

        counter = 0
        stop = False

        while not stop:
            time.sleep(SLEEP_LENGTH)
            counter += 1

            if idaapi.user_cancelled():
                print("GhIDA:: [!] decompilation interrupted.")
                stop = True
                continue

            if counter > COUNTER_MAX:
                print("GhIDA:: [!] Timeout reached.")
                stop = True
                continue

            if not t1.isAlive():
                stop = True
                print("GhIDA:: [DEBUG] Thread terminated.")
                continue

        print("GhIDA:: [DEBUG] Joining decompilation thread.")
        t1.join(0)
        q_result = queue.get_nowait()
        print("GhIDA:: [DEBUG] Thread joined. Got queue result.")
        idaapi.hide_wait_box()
        return q_result

    except Exception:
        idaapi.hide_wait_box()
        print("GhIDA:: [!] Unexpected decompilation error")
        idaapi.warning("GhIDA decompilation error")
        return None


# ------------------------------------------------------------
#   DECOMPILE FUNCTION - CORE
# ------------------------------------------------------------

def decompile_function(address,
                       use_ghidra_server,
                       ghidra_headless_path,
                       ghidra_plugins_path,
                       ghidra_server_url):
    """
    Decompile function at address @address
    """
    try:
        print("GhIDA:: [DEBUG] Decompiling %s" % address)

        xml_file_path, bin_file_path = export_ida_project_to_xml()

        # Get the decompiled code
        if use_ghidra_server:
            decompiled = ghidraaas_decompile(address,
                                             xml_file_path,
                                             bin_file_path,
                                             ghidra_server_url)
        else:
            decompiled = ghidra_headless(address,
                                         xml_file_path,
                                         bin_file_path,
                                         ghidra_headless_path,
                                         ghidra_plugins_path)
        return decompiled

    except Exception:
        print("GhIDA:: [!] Decompilation error")
        idaapi.warning("GhIDA decompilation error")
