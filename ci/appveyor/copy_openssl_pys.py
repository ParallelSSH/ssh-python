#! -*- Encoding: utf-8 -*-

import os
import sys
import shutil
import re

def extension(filename):
    k = filename.rfind(".")
    if k > 0:
        return filename[k:].lower()
        
def change_extension(filename, new_extension):
    k = filename.rfind(".")
    if k > 0:
        return filename[:k] + new_extension
        
    return filename + new_extension

def ensure_files(target, source):
    try:
        print("%r => %r" % (source, target, ))
        for filename in os.listdir(target):
            if extension(filename) in (".dll", ".exe", ):
                source_path = os.path.join(source, change_extension(filename, ".pdb"))
                if os.path.exists(source_path):
                    target_path = os.path.join(target, change_extension(filename, ".pdb"))
                    print("copy %r => %r" % (source_path, target_path, ))
                    shutil.copy2(source_path, target_path)
    except:
        pass
        
def main(openssl_version):
    for vs in ("vs2010", "vs2013", "vs2015"):
        for architecture in ("win32", "win64"):
            bitness = "32bit"
            if architecture == "win64":
                bitness = "64bit"
            
            for build in ("release", "debug"):
                target_name = "t:\\openssl-%s-%s-%s-%s" % (openssl_version, bitness, build, vs, )
                build_name = ""
                if build == "debug":
                    build_name = ".dbg"
                source_name = "t:\\openssl-src-%s-%s\\out32dll%s" % (architecture, vs, build_name, )
                ensure_files(os.path.join(target_name, "bin"), source_name)
                ensure_files(os.path.join(target_name, "lib\\engines"), source_name)

if __name__ == "__main__":
    #main("1.0.0m")
    for filename in os.listdir("."):
        if filename.endswith(".tar.gz"):
            if filename.startswith("openssl-"):
                main(filename[8:-7])
    