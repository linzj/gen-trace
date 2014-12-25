"""
Filter the output of readelf -sW
"""
import sys,re
processed_sym = {}

def filer_line (s, output_file):
    if not s:
        return
    elems = s.split()
    if 8 != len(elems):
        return
    if elems[7] in processed_sym:
        return
    if elems[3] != "FUNC":
        return
    if elems[6] == "UND":
        return
    sym_base = elems[1]
    size = elems[2]
    sym_name = elems[7]
    processed_sym[sym_name] = None
    print >> output_file, sym_base
    print >> output_file, size
    print >> output_file, sym_name

def do_filer (input_file, output_file):
    while True:
        l = input_file.readline ()
        if not l:
            break
        filer_line (l.rstrip(), output_file)

def main ():
    do_filer (sys.stdin, sys.stdout)

if __name__ == '__main__':
    main()
