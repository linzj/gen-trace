import sys, os, struct

class ParseException(Exception):
    pass

class RecordException(Exception):
    pass


class Recorder(object):
    def __init__(self, writer):
        self.m_writer = writer
        self.m_stacks = {}
        self.actionEnter = 0
        self.actionExit = 1
        self.actionUnroll = 2

    def record(self, tid, methodAddress, action, threadTime, wallTime):
        if action == self.actionEnter:
            if tid in self.m_stacks:
                stack = self.m_stacks[tid]
            else:
                stack = []
                self.m_stacks[tid] = stack
            stack.append((tid, methodAddress, threadTime, wallTime,))
        else:
            if not tid in self.m_stacks:
                return
            stack = self.m_stacks[tid]
            if not stack:
                return
            topMethodAddress = stack[-1][1]
            if topMethodAddress != methodAddress:
                raise RecordException("invalid record: unmatched method address")
            threadStart = stack[-1][2]
            threadDur = threadTime - threadStart
            wallStart = stack[-1][3]
            wallDur = wallTime - wallStart
            stack.pop()
            self.m_writer.write(tid, methodAddress, threadStart, threadDur, wallStart, wallDur)

class Writer(object):
    def __init__(self, outputFile, context):
        self.m_outputFile = outputFile
        self.m_context = context
        self.worker = self.initWorker
        self.m_startWall = 0

    def write(self, tid, methodAddress, threadStart, threadDur, wallStart, wallDur):
        self.worker(tid, methodAddress, threadStart, threadDur, wallStart, wallDur)

    def initWorker(self, tid, methodAddress, threadStart, threadDur, wallStart, wallDur):
        self.worker = self.writeRecord
        self.writeHeader()
        self.writeRecord(tid, methodAddress, threadStart, threadDur, wallStart, wallDur)

    def writeRecord(self,tid, methodAddress, threadStart, threadDur, wallStart, wallDur):
# "{\"cat\":\"%s\", \"pid\":%d, \"tid\":%d, \"ts\":%" PRIu64 ", "
# "\"ph\":\"X\", \"name\":\"%s\", \"dur\": %" PRIu64 "}",
# "profile", current->pid_, current->tid_, current->start_time_,
# current->name_, current->dur_);
        self.m_outputFile.write(',{"cat":"profile","pid":1,"tid":%d,"ts":%d,"ph":"X","name":"%s","dur":%d,"tts":%d,"tdur":%d}' % (tid, wallStart + self.m_startWall, self.m_context.getMethodName(methodAddress), wallDur, threadStart, threadDur))

    def writeHeader(self):
        #{"cat":"__metadata","pid":3649,"tid":10,"ts":0,"ph":"M","name":"thread_name","args":{"name":"Chrome_ChildIOThread"}}
        self.m_outputFile.write('{"traceEvents":[')
        needComma = False
        for tid, name in self.m_context.getThreadInfo().items():
            if not needComma:
                needComma = True
            else:
                self.m_outputFile.write(',')
            self.m_outputFile.write('{"cat":"__metadata","pid":1,"tid":%d,"ts":0,"ph":"M","name":"thread_name","args":{"name":"%s"}}' % (tid, name))
        self.m_startWall = self.m_context.getStartWall()
    def end(self):
        self.m_outputFile.write(']}')

class Parser(object):
    def __init__(self, inputFile, outputFile):
        self.m_inputFile = inputFile
        self.m_outputFile = outputFile
        self.m_numMethodCalls = 0
        self.m_threadInfo = {}
        self.m_methodInfo = {}
        self.m_writer = Writer(outputFile, self)
        self.m_recorder = Recorder(self.m_writer)
        self.m_recordSize = 0
        self.m_startWall = 0L

    def parse(self):
       self.workoutHeader()
       self.workoutThreads()
       self.workoutMethods()
       self.workoutRecords() 
       self.m_writer.end()

    def nextLine(self):
        line = self.m_inputFile.readline()
        if not line:
            raise ParseException("Not expecting empty line")
        return line.rstrip()

    def workoutHeader(self):
        line = self.nextLine()
        if line != "*version":
            raise ParseException("Expecting *version")
        line = self.nextLine()
        if line != "3":
            raise ParseException("Expecting version 3")
        line = self.nextLine()
        if not line.startswith("data-file-overflow="):
            raise ParseException("Expecting data-file-overflow=")
        line = self.nextLine()
        if line != "clock=dual":
            raise ParseException("Expecting clock=dual")
        line = self.nextLine()
        if not line.startswith("elapsed-time-usec="):
            raise ParseException("Expecting elapsed-time-usec=")
        line = self.nextLine()
        if not line.startswith("num-method-calls="):
            raise ParseException("Expecting num-method-calls=")
        self.m_numMethodCalls = int(line[len("num-method-calls="):])
        line = self.nextLine()
        if not line.startswith("clock-call-overhead-nsec="):
            raise ParseException("Expecting clock-call-overhead-nsec=")

        line = self.nextLine()
        if line != "vm=dalvik":
            raise ParseException("Expecting vm=dalvik")
        line = self.nextLine()
        if line != "*threads":
            raise ParseException("Expecting *thread, but " + line)

    def workoutThreads(self):
        while True:
            line = self.nextLine()
            if line[0] == '*':
                #This should be the end of workoutThreads.
                if line != "*methods":
                    raise ParseException("Expecting *methods")
                return
            _tuple = line.split()
            if len(_tuple) < 2:
                raise ParseException("line: " + line + " should be splittable")
            tid = int(_tuple[0])
            name = ' '.join(_tuple[1:])
            self.m_threadInfo[tid] = name

    def workoutMethods(self):
        while True:
            line = self.nextLine()
            if line[0] == '*':
                #This should be the end of workoutThreads.
                if line != "*end":
                    raise ParseException("Expecting *end")
                return
            _tuple = line.split()
            if len(_tuple) != 6:
                raise ParseException("line: " + line + " should be splittable")
            address = int(_tuple[0], 16)
            methodName = _tuple[1].replace('/', '.') + '.' + _tuple[2]
            self.m_methodInfo[address] = methodName

    def workoutRecords(self):
        self.workoutRecordHeader()
        _struct = struct.Struct("<HIII")
        actionMask = 4 - 1
        methodMask = ~actionMask
        readBytes = 0
        while True:
            _buffer = self.m_inputFile.read(2 + 4 + 4 + 4)
            if not _buffer:
                return
            readBytes += 2 + 4 + 4 + 4
            _tuple = _struct.unpack(_buffer)
            tid = _tuple[0]
            methodAndAction = _tuple[1]
            threadTime = _tuple[2]
            wallTime = _tuple[3]

            methodAddress  = methodAndAction & methodMask
            action = methodAndAction & actionMask
            #print >>sys.stderr, "tid: {0}, methodName: {1}, action: {2}, threadTime: {3}, wallTime: {4}".format(tid, self.getMethodName(methodAddress), action, threadTime, wallTime)
            self.m_recorder.record(tid, methodAddress, action, threadTime, wallTime)

    def workoutRecordHeader(self):
        _struct = struct.Struct("<IHHQH")
        _buffer = self.m_inputFile.read(18)
        _tuple = _struct.unpack(_buffer)
        if _tuple[0] != 0x574f4c53:
            raise ParseException("Expecting TRACE_MAGIC equals 0x574f4c53")
        if _tuple[1] != 3:
            raise ParseException("Expecting version 3")
        headerSize = _tuple[2]
        self.m_startWall = _tuple[3]
        if _tuple[4] != 14:
            raise ParseException("Expecting record size 14")
        shouldRead = headerSize - 18
        self.m_inputFile.read(shouldRead)

    def getMethodName(self, address):
        return self.m_methodInfo[address]

    def getThreadInfo(self):
        return self.m_threadInfo

    def getStartWall(self):
        return self.m_startWall



def doWork(inputFile, outputFile):
    parser = Parser(inputFile, outputFile)
    parser.parse()

def main():
    if len(sys.argv) < 2:
        usage()
    fileName = sys.argv[1]
    if not os.path.isfile(fileName):
        usage()
    with open(fileName, 'rb') as inputFile:
        if len(sys.argv) >= 3:
            outputFileName = sys.argv[2]
            if not os.path.isdir(outputFileName):
                with open(outputFileName, 'w') as outputFile:
                    doWork(inputFile, outputFile)
                    return

        doWork(inputFile, sys.stdout)

if __name__ == '__main__':
    main()
