import json, sys, os

name_count = {}
threshold = 10000

def record_element (e):
    name = e["name"]
    if name in name_count:
        name_count[name] += 1
    else:
        name_count[name] = 1

def reconstruct_array (a):
    a1 = []
    for e in a:
        name = e["name"]
        if name_count[name] >= threshold:
            continue
        a1.append (e)
    return a1

def reduce_array (a):
    for element in a:
        record_element (element)
    return reconstruct_array (a)

def handle_file (f):
    o = json.load (f)
    o["traceEvents"] = reduce_array (o["traceEvents"])
    return o

def is_ended (f):
    f.seek (-2, os.SEEK_END)
    end_2 = f.read ()
    if end_2 != "]}":
        return False
    return True

def write_ended (f):
    f.write (']}')

def main ():
    if len (sys.argv) != 2:
        print >>sys.stderr, "need a json file path"
    with open (sys.argv[1], 'r') as f:
        _is_ended = is_ended (f)
    if not _is_ended:
        with open (sys.argv[1], 'a') as f:
            write_ended (f)
    with open (sys.argv[1], 'r') as f:
        o = handle_file (f)

    sys.stdout.write(json.dumps (o))

if __name__ == '__main__':
    main ()
