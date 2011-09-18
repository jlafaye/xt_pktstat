import time
import datetime

class CsvWriter:

    def __init__(self, filename):
        import csv
        self.csv = csv.writer(open(filename, 'wb'))

    def onValue(self, value):
        self.csv.writerow(value)

def timestampToDatetime(tstamp):
    total_secs  = tstamp  / 1000000000
    total_usecs = (tstamp % 1000000000) / 1000
    return datetime.datetime.fromtimestamp(total_secs), total_usecs

class ConsoleWriter:

    def __init__(self, emptyLines=True):
        self.count    = 0
        self.previousTimestamp = None
        self.deltaTimestamp    = None
        self.emptyLines        = emptyLines

    def printLine(self, tstamp, pkts, Bytes, pktRate, byteRate):
        now, total_usecs = tstamp
        tstamp_str = "%02d:%02d:%02d.%03d" % (now.hour, now.minute, now.second, total_usecs/1000)
        pkt_str      = "%6d" % pkts
        byte_str     = "%6d" % Bytes
        pktrate_str  = ("%6.2f" % pktRate)  if pktRate  is not None else ("%6s" % "N/A")
        byterate_str = ("%6.2f" % byteRate) if byteRate is not None else ("%6s" % "N/A")
        if self.count == 0:
            self.count = 10
            print "    time       pkts  bytes  pkt/s   kB/s"
        print tstamp_str, pkt_str, byte_str, pktrate_str, byterate_str

    def onValue(self, value):
        tstamp = value[0]
        deltaTimestamp = None
        if self.previousTimestamp is not None:
            deltaTimestamp = tstamp - self.previousTimestamp
            if self.deltaTimestamp > deltaTimestamp or self.deltaTimestamp is None:
                self.deltaTimestamp = deltaTimestamp

        pktRate  = None 
        byteRate = None

        if self.previousTimestamp is not None:
            curr = self.previousTimestamp + self.deltaTimestamp
            while curr < tstamp:
                self.printLine(timestampToDatetime(curr), 0, 0, 0, 0)
                curr = curr + self.deltaTimestamp
            pktRate  = 1000000000 * float(value[1]) / deltaTimestamp
            byteRate = 1000000 * float(value[2])    / deltaTimestamp
            
        self.printLine(timestampToDatetime(tstamp), value[1], value[2], pktRate, byteRate) 
    
        self.count = self.count - 1
        self.previousTimestamp = tstamp


class StatReader:
    
    def __init__(self, filename): 
        self.filename = filename 
        self.previous = None
    
    def read(self):
        f = open(self.filename) 
        for line in f:
            current = [int(n) for n in line.split()]
            if len(current) != 3:
                continue
            if self.previous is None:
                self.previous = current
                continue
            if current[0] < self.previous[0]:
                continue
            print current[0], current[1]-self.previous[1], current[2]-self.previous[2]
            self.previous = current

    def processLine(self, line):
        current = [int(n) for n in line.split()]
        if len(current) != 3:
            return None
        if self.previous is None:
            self.previous = current
            return None
        if current[0] <= self.previous[0]:
            return None
        ret = current[0], current[1]-self.previous[1], current[2]-self.previous[2]
        self.previous = current
        return ret

    def __iter__(self):
        self.file = open(self.filename)
        return self

    def next(self):
        try:
            while True:
                line  = self.file.next()
                item  = self.processLine(line)
                if item is not None: return item
        except StopIteration:
            # TODO: close file
            raise StopIteration
    

class Multiplexer:

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
       
    def run(self): 
        while True:
            for item in self.reader:
                # print item
                self.writer.onValue(item)
            time.sleep(1)

def usage():
    import sys
    print """Usage: %s [OPTION] .. [OPTION]
  -h, --help    display this page
  -i, --statid  select statid""" % sys.argv[0]

def main():
    import sys, getopt
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:", [ "help", "statid" ])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(-1)
    statId = 0
    output = None
    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-i", "--statid"):
            statId = int(a)
        else:
            assert False, "unhandled option"
    
    filename = "/proc/net/xt_pktstat/%d/data" % statId
    print "+++ using %s" % filename

    sr = StatReader(filename)
    cw = ConsoleWriter()
    m  = Multiplexer(sr, cw)
    m.run()

if __name__ == "__main__":
    main()
    
