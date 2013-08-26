#!/usr/bin/python

# Split source code files into XML snippets for inclusion in the
# documentation.
#
# Usage: python split-snippets.py TARGET-ROOT INPUT-FILE...
#
# Directives in the input files have the form:
#
#   //+ Directory File-Base-Name
#   lines to be included in
#   the file
#   //-
#
# In this example, the lines are written to the file
# en-US/Directory/snippets/File-Base-Name.xml under the TARGET-ROOT
# directory.  Whitespace shared with the starting line is stripped.
# Instead of "//", it is possible to use "#".

import re
import sys

target_root = sys.argv[1]

def output_file_name(dirname, basename):
    return "{0}/en-US/snippets/{1}-{2}.xml".format(
        target_root, dirname, basename)

re_open_file = re.compile(
    r'^(\s*)(?://|#)\+\s+([a-zA-Z0-9_-]+)\s+([a-zA-Z0-9_-]+)\s*\n?$')
re_close_file = re.compile(r'^\s*(?://|#)\-\s*\n?$')

def extension_to_language(path, map={
        'c' : 'C',
        'py' : 'Python',
        'java' : 'Java',
        }):
    return map.get(path.split('.')[-1], 'C')

def write_single_file(path, contents, language):
    assert not [ch for ch in language if ch in "<>&\""]
    with file(path, "w") as out:
        out.write('''<?xml version='1.0' encoding='utf-8' ?>
<!DOCTYPE programlisting PUBLIC "-//OASIS//DTD DocBook XML V4.5//EN" "http://www.oasis-open.org/docbook/xml/4.5/docbookx.dtd" [
]>
<!-- Automatically generated file.  Do not edit. -->
<programlisting language="''' + language + '''">
''')
        for line in contents:
            for ch in line:
                if ch in "<>&":
                    out.write("&#{0};".format(ord(ch)))
                else:
                    out.write(ch)
        out.write("</programlisting>\n")

def write_output(output):
    for (outpath, (origpath, contents)) in output.items():
        write_single_file(outpath, contents,
                          extension_to_language(origpath))

def process_file(path):
    output = {}
    with file(path) as f:
        current_file = None
        current_contents = None
        indent = None
        for line in f.readlines():
            match = re_open_file.match(line)
            if match is not None:
                if current_file is None:
                    current_file = output_file_name(
                        match.group(2), match.group(3))
                    if current_file in output:
                        raise IOError("{0} written by {1} and {2}",
                                      current_file, output[current_file][0],
                                      path)
                    indent = match.group(1)
                    current_contents = []
                    output[current_file] = (path, current_contents)
                else:
                    raise IOError("{0}: unterminated export to {1}".format(
                            path, current_file))
                continue

            match = re_close_file.match(line)
            if match is not None:
                if current_file is None:
                    raise IOError("{0}: closing file which is not open")
                else:
                    current_file = None
                    current_contents = None
                    indent = None
                continue

            if current_file is not None:
                if line.startswith(indent):
                    line = line[len(indent):]
                current_contents.append(line)
        if current_file is not None:
            raise IOError("{0}: unterminated export to {1}".format(
                    path, current_file))
    write_output(output)

for path in sys.argv[2:]:
    process_file(path)
