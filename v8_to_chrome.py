import os, sys, re

class ParseException(Exception):
    pass

class RecordException(Exception):
    pass

class Writer(object):
    def __init__(self, outputFile):
        self.m_outputFile = outputFile
        self.m_stack = []
        self.m_curDepth = 0
        self.m_curTime = 0
        self.m_needComma = False
        self.writeHeader()


    def handleEntry(self, entry):
        depth = entry[0]
        functionName = entry[1]
        #print "depth: %d, functionName: %s, self.m_curDepth = %d" % (depth, functionName, self.m_curDepth)
        if depth <= self.m_curDepth:
            if self.m_curDepth == 0:
                raise ParseException()
            self.recordTop()
            self.pop()
            while depth < self.m_curDepth:
                self.recordTop()
                self.pop()
        elif depth > self.m_curDepth:
            self.pushEntry(functionName)
        curDepth = self.m_curDepth
        if curDepth != depth and curDepth != depth - 1:
            raise ParseException("self.m_curDepth = %d, depth = %d" % (curDepth, depth))

    def writeHeader(self):
        self.m_outputFile.write('{"traceEvents":[')

    def recordTop(self):
        entry = self.m_stack[-1]
        functionName, startTime = entry
        if self.m_needComma:
            self.m_outputFile.write(',')
        else:
            self.m_needComma = True
        if not functionName:
            functionName = "Unknown"
        self.m_curTime += 1
        endTime = self.m_curTime

        self.m_outputFile.write('{"cat":"profile","pid":1,"ts":%d,"ph":"X","name":"%s","dur":%d}' % (startTime, functionName, endTime - startTime))

    def pop(self):
        self.m_stack.pop()
        self.m_curDepth -= 1

    def end(self):
        self.flush()
        assert self.m_curDepth == 0 and len(self.m_stack) == 0
        self.m_outputFile.write(']}')

    def pushEntry(self, functionName):
        self.m_curTime += 1
        self.m_curDepth += 1
        startTime = self.m_curTime
        self.m_stack.append((functionName, startTime))

    def flush(self):
        while self.m_stack:
            self.recordTop()
            self.pop()

lineRe = re.compile('\s+(\d+):\s+(\w*)(?:\+\d+)?.*')
lineCount = 1

def parse(inputFile):
    global lineRe, lineCount
    while True:
        line = inputFile.readline()
        if not line:
            return None
        m = lineRe.match(line)
        if m:
            break
    # print ""
    # print "line #%d" % lineCount
    lineCount += 1
    return (int(m.group(1)), m.group(2))

def doWork(inputFile, outputFile):
    w = Writer(outputFile)
    while True:
        entry = parse(inputFile)
        if not entry:
            break
        w.handleEntry(entry)
    w.end()
    


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
