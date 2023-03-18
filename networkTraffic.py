import pyshark
import csv

class networkTraffic:
    def __init__(self, networkInterface, logFile, TimeOut, PacketFilter, PacketsRefreshLimit, fileDirectionCSV, filenameCSV):
        # Instance Variable
        self.networkInterface = networkInterface
        self.logFile = logFile
        self.TimeOut = TimeOut
        self.PacketFilter = PacketFilter
        self.PacketsRefreshLimit = PacketsRefreshLimit
        self.fileDirectionCSV = fileDirectionCSV
        self.filenameCSV = filenameCSV

    def sniffer(self, captureData):
        self.captureData = captureData
        self.captureData.sniff(timeout=self.TimeOut)
        return self.captureData
    
    def Reader(self, captureSave=False, capturePost=True):
        Capture = pyshark.LiveCapture(interface=self.networkInterface)
        print("wait for the packets", end="\r")
        packetsList = []
        for raw_packet in Capture.sniff_continuously():
            if self.PacketDetails(raw_packet, filtering=self.PacketFilter) != False:
                if capturePost == True:
                    print(self.PacketDetails(raw_packet, filtering=self.PacketFilter))
                if captureSave == True:
                    packetsList.append( self.PacketDetails(raw_packet, filtering=self.PacketFilter) )
                    print( self.PacketDetails(raw_packet, filtering=self.PacketFilter) )
                    if len(packetsList) + 1 > self.PacketsRefreshLimit:
                        self.csvGeneration(packetsList)
                        packetsList = []
                        print("refreshed")
                        break

    def csvGeneration(self, data):
        self.data = data
        # field names
        fields = ['protocolType', 'sourceAddress', 'sourcePort', 'destinationAddress', 'destinationPort', 'packetTime', 'Bytes']

        # name of csv file
        filename = self.fileDirectionCSV + self.filenameCSV + ".csv"
        
        # writing to csv file

        with open(filename, 'w', encoding='UTF8') as csvfile:
            writer = csv.writer(csvfile) #this is the writer object
            writer.writerow(fields) # this will list out the names of the columns
            
            for indexData in self.data:
                writer.writerow(indexData)

    # Configraution Data Functions
    def PacketDetails(self, pkt, filtering = 'tcp'):
        self.pkt = pkt
        self.filtering = filtering
        if hasattr(self.pkt, self.filtering):
            try:
                protocol = self.pkt.transport_layer
                src_addr = self.pkt.ip.src
                src_port = self.pkt[self.pkt.transport_layer].srcport
                dst_addr = self.pkt.ip.dst
                dst_port = self.pkt[self.pkt.transport_layer].dstport
                pkt_time = self.pkt.sniff_time
                pkt_time = str(pkt_time)
                pkt_bytes = int(self.pkt.length)
                #{'protocol': protocol,'src_addr': src_addr,'src_port': src_port,'dst_addr': dst_addr,'dst_port':dst_port, 'pkt_time':pkt_time, 'pkt_bytes': pkt_bytes}
                return [protocol , src_addr, src_port, dst_addr, dst_port, pkt_time, pkt_bytes] 
                #print('%s  %s:%s --> %s:%s' % (protocol, src_addr, src_port, dst_addr, dst_port))
            except AttributeError as e:
                #ignore packets that aren't TCP/UDP or IPv4
                pass
        return False



properties = {'networkInterface': 'Wi-Fi', # here your network interface like(en0, Wi-Fi, ...)
              'logFile': 'CaptureData' # Capture data file name (chosed)
              + '.csv', # Capture data file format as .pcap
              'TimeOut': 10, # Capturing Data Waiting for Timed Out in (sec) for get packets
              'PacketFilter': 'tcp', # Packet Type
              'PacketsRefreshLimit': 5, # Max Packet that write in .csv file
              'fileDirectionCSV': '/Users/mohammedalziyad/Desktop/', # file direction
              'filenameCSV': 'trafficFile'} # the max packets that printed


nt = networkTraffic(properties['networkInterface'], 
                    properties['logFile'], 
                    properties['TimeOut'], 
                    properties['PacketFilter'], 
                    properties['PacketsRefreshLimit'], 
                    properties['fileDirectionCSV'], 
                    properties['filenameCSV'])
nt.Reader(captureSave=True, capturePost=False)
