import sys
white_key_words = (
)

black_key_words = (
'std::',
'<',
'~',
)

def has_white_key_word(_str):
    if not white_key_words:
        return True
    for key_word in white_key_words:
        if key_word in _str:
            return True
    return False

def has_black_key_words(_str):
    for key_word in black_key_words:
        if key_word in _str:
            return True
    return False

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
        if l3.startswith ('__') or has_black_key_words (l3):
            continue
        if not has_white_key_word(l3):
            continue
        function_name = l3.rstrip ()
        find_start = 0
        while True:
            left_parenthesis = function_name.find ('(', find_start)
            if -1 != left_parenthesis:
                find_start = left_parenthesis + 1
                if function_name[find_start:].startswith('anonymous namespace)'):
                    continue
                function_name = function_name[:left_parenthesis]
                break
            else:
                break
        print >>output_file, l1.rstrip ()
        print >>output_file, l2.rstrip ()
        print >>output_file, function_name

def main ():
    filter_file (sys.stdin,sys.stdout)
if __name__ == '__main__':
    main()
