
import pcap
import sys
import re

import struct

class Data:
    #list of dictionaries {host: '', path: '', ip: ''} 
    requests = []
    
    # contains data structured by hosts:
    # host['google.com'] = {'?q=whatever': {'count': 4, ips: []}}
    hosts = dict()
    
    def addRequest(self, host, path, ip):
        self.requests.append({'host': host, 'path': path, 'ip': ip})
        
        if not host in self.hosts:
            self.hosts[host] = {}
        if not path in self.hosts[host]:
            self.hosts[host][path] = {'count': 0, 'ips': []}
        
        data = self.hosts[host][path]
        
        data['count'] += 1
        if not ip in data['ips']:
            data['ips'].append(ip)
    
    def toString(self, human=True, nestByHost=True, showIps=True, showCount=True):
        string = ''
        
        for host in self.hosts:
            string += host + ':' + '\n'
            
            for path, data in self.hosts[host].items():
                string += '    ' + path
                if showCount: string += '(' + str(data['count']) + ')'
                string += '\n'
                
                if showIps:
                    for ip in data['ips']:
                        string += '        ' + ip + '\n'
        return string
            
            
        
class Sniffer:
    
    data = Data()
    
    sniffer = None
    
    newRequestCallback = None
    
    def prepare(self, interface):
        sniffer = pcap.pcapObject()
        net, mask = pcap.lookupnet(interface)
        
        sniffer.open_live(interface, 1600, 0, 100)
        sniffer.setfilter('tcp port 80', 0, 0)
        
        self.sniffer = sniffer
    
    def  run(self, stopOnNoResult=True, maxIterations=None):
        flag = True
        counter = 0
        
        try:
            while flag:
                data = self.sniffer.next()
                
                if data == None:
                    if stopOnNoResult: break
                else:
                    self.handleData(data)
                    ++counter
                
                if maxIterations:
                    maxIterations -= 1
                    if maxIterations < 1: break
                    
        except Exception as e:
            print e
            return False
        
        return counter
                
        #except KeyboardInterrupt:
            #print '%s' % sys.exc_type
            #print 'shutting down'
            #print '%d packets received, %d packets dropped, %d packets dropped by interface' % sniffer.stats()
    
    def stop(self):
        self.sniffer.stats()
    
    def handleData(self, data):
        len, data, timestamp = data
        request = self.parsePacket(data)
        
        if request: 
            self.data.addRequest(*request)
            
            if self.newRequestCallback: self.newRequestCallback(request)
        
    def parsePacket(self, data):
        host = re.search('host\:\s(.*?)\r?\n', data, re.IGNORECASE)
        if host: host = host.group(1)
        
        path = re.search('GET\s(.*?)\s', data, re.IGNORECASE)
        if path: path = path.group(1)
        
        ip = pcap.ntoa(struct.unpack('i',data[14:][12:16])[0])
        
        if host and path and ip: return (host, path, ip)
        else: return None
    