#!/usr/bin/python

# Usage: python check-function.py DSO/FUNCTION-NAME/OUTPUT
#
# Prints OUTPUT if libDSO.so can be loaded and defines FUNCTION-NAME
# as a function, or nothing otherwise.

import ctypes
import sys

for (dsoname, funcname, output) in [arg.split("/", 3)
                                    for arg in sys.argv[1:]]:
    try:
        dso = ctypes.CDLL("lib{0}.so".format(dsoname))
    except OSError:
        continue
    if getattr(dso, funcname, None) is not None:
        print output
