import gdb, os, re, traceback
import ctypes, os

CLOCK_MONOTONIC_RAW = 4 # see <linux/time.h>

class timespec(ctypes.Structure):
    _fields_ = [
        ('tv_sec', ctypes.c_long),
        ('tv_nsec', ctypes.c_long)
    ]

librt = ctypes.CDLL('librt.so.1', use_errno=True)
clock_gettime = librt.clock_gettime
clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(timespec)]

def monotonic_time():
    t = timespec()
    if clock_gettime(CLOCK_MONOTONIC_RAW , ctypes.pointer(t)) != 0:
        errno_ = ctypes.get_errno()
        raise OSError(errno_, os.strerror(errno_))
    return t.tv_sec + t.tv_nsec * 1e-9

MAX_STACK = 50
class Writer(object):
    def __init__(self, outputFile):
        self.m_outputFile = outputFile
        self.m_stack = []
        self.m_curDepth = 0
        self.m_curTime = 0
        self.m_needComma = False
        self.writeHeader()

    def writeHeader(self):
        self.m_outputFile.write('{"traceEvents":[')

    def record(self, entry):
        if self.m_curDepth >= MAX_STACK:
            return
        functionName, startTime = entry
        if not functionName:
            return
        if self.m_needComma:
            self.m_outputFile.write(',')
        else:
            self.m_needComma = True
        endTime = monotonic_time()

        self.m_outputFile.write('{"pid":1,"ts":%d,"ph":"X","name":"%s","dur":%d}' % (startTime * 1e6, functionName, (endTime - startTime) * 1e6))

    def pop(self):
        actualPop = None
        if self.m_curDepth <= MAX_STACK:
            actualPop = self.m_stack.pop()
        self.m_curDepth -= 1
        assert self.m_curDepth >= len(self.m_stack)
        return actualPop

    def end(self):
        self.flush()
        assert self.m_curDepth == 0 and len(self.m_stack) == 0
        self.m_outputFile.write(']}')
        self.m_outputFile.flush()
        self.m_outputFile.close()

    def push(self, functionName):
        self.m_curDepth += 1
        if self.m_curDepth > MAX_STACK:
            return
        startTime = monotonic_time()
        if startTime <= self.m_curTime:
            self.m_curTime += 1
            startTime = self.m_curTime
        else:
            self.m_curTime = startTime
        self.m_stack.append((functionName, startTime))

    def flush(self):
        while self.m_stack:
            e = self.pop()
            if e:
                self.record(e)

class ThreadInfo(object):
    def __init__(self, num):
        self.num_ = num
        self.stack_ = []
        self.frame_ret_count_ = {}

    def append_frame(self, addr, func_name, prev_pc):
        self.stack_.append((addr, func_name))
        if prev_pc in self.frame_ret_count_:
            self.frame_ret_count_[prev_pc] += 1
        else:
            self.frame_ret_count_[prev_pc] = 1
        return self.frame_ret_count_[prev_pc]

    def dec_frame(self, prev_pc):
        if prev_pc in self.frame_ret_count_:
            self.frame_ret_count_[prev_pc] -= 1
            if self.frame_ret_count_[prev_pc] == 0:
                del self.frame_ret_count_[prev_pc]
                return 0
            return self.frame_ret_count_[prev_pc]
        return 0
    def top_addr(self):
        return self.stack_[-1][0]
    def pop(self):
        return self.stack_.pop()

g_tinfo = {}
g_writer = None

def parse_functions_string(functions_string, break_forever):
    myre = re.compile('[a-zA-Z0-9:_]+\(')
    myset = {}
    for function_string in functions_string.splitlines():
        m = myre.search(function_string)
        debug_file.write('%s\n' % function_string)
        if m:
            fun_name_str = function_string[m.start():m.end() - 1]
            if fun_name_str.startswith('::'):
                fun_name_str = '(anonymous namespace)' + fun_name_str
            if '@plt' in fun_name_str:
                continue
            if fun_name_str in myset:
                continue
            myset[fun_name_str] = None
            break_forever(fun_name_str)

g_ret_bps = {}

def break_for_ret(addr, prev_addr, func_name, tid):
    if tid in g_ret_bps:
        if prev_addr in g_ret_bps[tid]:
            return
        else:
            g_ret_bps[tid][prev_addr] = None
            MyBreakReturn(addr, prev_addr, func_name, tid)
    else:
        tmp_dict = {}
        tmp_dict[prev_addr] = None
        g_ret_bps[tid] = tmp_dict
        MyBreakReturn(addr, prev_addr, func_name, tid)
debug_file = open('/tmp/debug_file', 'w')

class MyBreakForever(gdb.Breakpoint):
    def __init__(self, func_name):
        super().__init__(func_name, internal = True)
        self.func_name_ = func_name
        self.enabled = True
    def stop(self):
        try:
            # Setup return bp
            f = gdb.selected_frame()
            if not f:
                return
            old_f = f.older()
            if not old_f:
                return
            global g_writer
            g_writer.push(self.func_name_)
            t = gdb.selected_thread()
            tid = t.num
            global g_tinfo
            if tid in g_tinfo:
                tinfo = g_tinfo[tid]
            else:
                tinfo = ThreadInfo(tid)
                g_tinfo[tid] = tinfo
            if 1 == tinfo.append_frame(f.pc(), self.func_name_, old_f.pc()):
                """
                The first time in this thread hit this function
                """
                break_for_ret(f.pc(), old_f.pc(), self.func_name_, tid)
            
            #print("%s called" % self.func_name_)
            return False
        except Exception as e:
            traceback.print_exc()
            return False

class MyBreakReturn(gdb.Breakpoint):
    def __init__(self, addr, prev_addr, func_name, thread_id):
        super().__init__('*0x%x' % prev_addr, internal = True)
        self.thread_ = thread_id
        self.func_name_ = func_name
        self.thread_id_ = thread_id
        self.addr_ = addr
        self.prev_addr_ = prev_addr
        self.enabled = True

    def stop(self):
        try:
            global g_tinfo
            tinfo = g_tinfo[self.thread_id_]
            if tinfo.top_addr() == self.addr_:
                tinfo.pop()
                global g_writer
                e = g_writer.pop()
                if e:
                    g_writer.record(e)
                #print("%s returns" % self.func_name_)
                if 0 == tinfo.dec_frame(self.prev_addr_):
                    #print('deleteing return bp for %s' % self.func_name_)
                    """
                    self.delete()
                    is not available.
                    May get fix in the future.
                    """
            return False
        except Exception as e:
            traceback.print_exc()
            return False

def break_forever(func_name):
    MyBreakForever(func_name)

def gdb_init():
    """
    This function init by info function, parse what it returns.
    Break on each functions. When break, add a thread specific
    bp to where it will resume.
    """
    global g_writer
    g_writer = Writer(open('./trace.json', 'w'))
    functions_string = gdb.execute("info functions", to_string = True)
    parse_functions_string(functions_string, break_forever)

gdb_init()
