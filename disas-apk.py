#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""disas-apk
"""

# -------------------------------------[Imports]------------------------------------- #
import os
import sys
import argparse
import zipfile
import urllib.request
import re
import shutil
import datetime
from git import Repo

try:
    from tools.api_key_detector import detector
except ModuleNotFoundError:
    reimport = True # this is disgusting, I know. Sorry

# ----------------------------------------------------------------------------------- #

# ------------------------------------[Variables]------------------------------------ #
tool_path = {
    "root": "{}/tools".format(os.path.dirname(os.path.realpath(__file__)))
#   "jadx": ""
}

out_path = {
    "root": "{}/disas-output".format(os.getcwd())
}
# ----------------------------------------------------------------------------------- #

# ------------------------------------[Functions]------------------------------------ #
def write_log(msg, log_type="info"):
    if log_type == "info":
        prompt = "[-]"
    elif log_type == "warn":
        prompt = "[!]"
    elif log_type == "error":
        prompt = "[x]"
    else:
        prompt = "[~]"

    fmt_msg   = "[{0}] {1} {2}"
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")
    print(fmt_msg.format(timestamp, prompt, msg))

def install_tools():
    """Install 3rd party tools used by this script"""

    global tool_path, out_path

    original_cwd = os.getcwd()
    open(os.path.join(tool_path["root"], "__init__.py"), 'w').close()

    # Check if tools dir exists
    if not os.path.exists(tool_path["root"]):
        # If not, create it
        os.mkdir(tool_path["root"])

    # Download JADX
    jadx_uri = "https://github.com/skylot/jadx/releases/download/v1.1.0/jadx-1.1.0.zip"
    tool_path["jadx"] = os.path.join(tool_path["root"], "jadx")
    if not os.path.exists(tool_path["jadx"]): os.mkdir(tool_path["jadx"])
    os.chdir(tool_path["jadx"])

    jadx_zip = os.path.split(jadx_uri)[-1]
    urllib.request.urlretrieve(jadx_uri, os.path.join(tool_path["jadx"], jadx_zip))

    # Unzip JADX files
    os.system("jar xf {0}".format(os.path.join(tool_path["jadx"],
                                            jadx_zip)))

    # Set tool path
    if sys.platform == "win32":
        tool_path["jadx"] = os.path.join(tool_path["jadx"], "bin", "jadx.bat")
    else:
        tool_path["jadx"] = tool_path["jadx"] + "/bin/jadx"


    # Clone github repos
    github_repos = [
        {
            "url": "https://github.com/alessandrodd/api_key_detector.git",
            "dir": "api_key_detector"
        }
    ]

    for repo in github_repos:
        tool_path[repo["dir"]] = os.path.join(tool_path["root"], repo["dir"])
        if os.path.exists(tool_path[repo["dir"]]):
            Repo(tool_path[repo["dir"]]).git.pull()
        else:
            Repo.clone_from(repo["url"], tool_path[repo["dir"]])

    # Clean up
    os.remove(jadx_zip)
    os.chdir(original_cwd)

def decompile(apk_path):
    """Decompile an APK using Jadx and apktool

    Args:
        apk_path: Path to target APK

    """

    global out_path
    # Run apktool to get SMALI code
    # code here

    # Run Jadx to get java files from APK
    apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    out_path["jadx"] = os.path.join(out_path["root"], apk_name + "-gradle")
    jadx_cmd = "{0} -d {1} --deobf -e {2}"
    jadx_cmd = jadx_cmd.format(tool_path["jadx"],
                               out_path["jadx"],
                               apk_path)
    os.system(jadx_cmd)

def match_urls(target):
    """Match URLs and possible endpoints in a target string

    Args:
        target: String to search for URLs in

    Returns:
        Array that contains list of matches found in target string

    """
    reg_exp = re.compile(r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))")
    ignore_url = "http://schemas.android.com"
    results = []
    
    string_matches = reg_exp.findall(target)
    for match in string_matches:
        if ignore_url not in match[0]:
            results.append(match[0])

    return results

def match_api_keys(target):
    """Match possible API keys in a target string

    Args:
        target: String to search for API keys in

    Returns:
        Array that contains list of matches found in target string

    """
    # run alessandrodd/api_key_detector and daylen/api-key-detect
    if reimport:
        sys.path.insert(0, tool_path["root"])
        from api_key_detector import detector

    results = []

    # TODO: Filter out the input string a bit more first!
    words = target.replace('\'','').replace('\"','').split(' ')

    try:
        results = detector.filter_api_keys(words)
    except:
        results = []

    return results

def match_passwords(target):
    """Match possible hardcoded passwords in a target string

    Args:
        target: String to search for passwords in

    Returns:
        Array that contains list of matches found in targe-t string

    """
    reg_exp = re.compile(r"/password|pass|passwd/g")
        
    if reg_exp.match(target):
        return [target]
    else:
        return []

def scan_source_code():
    """Scans decompiled source code of the APK for various juicy info"""

    # Extensions of source files to scan
    extension_list = [
        ".java",
        ".xml",
        ".txt",
        ".json",
        ".js",
        ".html",
        ".ts",
    ]

    source_files = []

    matches = [
        {
            "function": match_urls,
            "output": "urls",
            "results": []
        },
        {
            "function": match_api_keys,
            "output": "api_keys",
            "results": []
        },
        {
            "function": match_passwords,
            "output": "passwords",
            "results": []
        }
    ]

    # Search through Jadx output for URIs
    for root, dirs, files in os.walk(out_path["jadx"]):

        # Iterate through the files
        for file_name in files:

            # Only search specified extensions
            if os.path.splitext(file_name)[1] not in extension_list:
                continue

            file_path = os.path.join(root, file_name)

            source_files.append(file_path)

    # Separate loop for readability
    for path in source_files:
        with open(path, 'r') as file_pointer:

            # Match each line individually
            for line in file_pointer:

                # Skip out empty lines
                if len(line.strip()) == 0:
                    continue

                # Go through all search functions
                for search in matches:
                    line_matches = search["function"](line.strip())
                    for match in line_matches:
                        short_path = file_path.replace(os.getcwd(), '')
                        search["results"].append("{0}:{1}".format(short_path, match))

    # Save output to files
    for search in matches:
        
        # Remove duplicates from results
        search["results"] = list(dict.fromkeys(search["results"]))

        # Set output path
        out_path[search["output"]] = os.path.join(out_path["root"], search["output"])

        # Write lines
        with open(out_path[search["output"]], 'a') as file_ptr:
            for match in search["results"]:
                file_ptr.writelines('\n'.join(search["results"]))
# ----------------------------------------------------------------------------------- #

# ------------------------------------[Main Logic]----------------------------------- #
def main(arguments):

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("apk")

    args = parser.parse_args(arguments)

    # Check if output directory already exists
    if os.path.exists(out_path["root"]):
        
        # Warn user
        write_log("Output directory already exists, running this again will overwrite previous output!", log_type="warn")
        write_log("Press enter to continue..")
        input()

        # If it does, clear it
        shutil.rmtree(out_path["root"])

    write_log("Updating..")
    install_tools()

    write_log("Decompiling APK")
    decompile(args.apk) 

    write_log("Analysing source code")
    scan_source_code()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
# ----------------------------------------------------------------------------------- #