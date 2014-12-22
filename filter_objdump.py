"""
Filter the output of objdump -tC
"""
import sys,re

hex_num = re.compile ('[0-9a-fA-F]{3,}')
space_or_tab = re.compile ('\s+')

def filer_line (s, output_file):
    global hex_num, space_or_tab
    if ".text" not in s:
        return
    m = hex_num.search (s)
    if not m or m.start () != 0:
        return
    sym_base = m.group (0)
    """
    not the 0 base.
    """
    if int (sym_base, 16) == 0:
        return
    m = hex_num.search (s, m.end ())
    if not m:
        return
    size = m.group (0)
    if int (size, 16) == 0:
        return
    m = space_or_tab.search (s, m.end ())
    if not m:
        return
    sym_name = s[m.end ():]
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
