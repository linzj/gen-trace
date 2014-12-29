import sys
def filter_file (input_file, output_file):
    input_file.readline ()
    input_file.readline ()
    input_file.readline ()
    while True:
        l1 = input_file.readline ()
        l2 = input_file.readline ()
        l3 = input_file.readline ()
        if not l1 or not l2 or not l3:
            break
        if l3.startswith('__') or 'operator' in l3:
            continue
        print >>output_file, l1.rstrip ()
        print >>output_file, l2.rstrip ()
        print >>output_file, l3.rstrip ()

def main ():
    filter_file (sys.stdin,sys.stdout)
if __name__ == '__main__':
    main()
