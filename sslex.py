#!/usr/bin/env python
#
# Copyright 2014 Shoufu Luo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os, sys
import pickle

p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dpkt-1.8')
if p not in sys.path:
    sys.path.insert(0, p)

import dpkt

def pcap_extractor(filename):
    with open(filename, 'rb') as fp:
        pcap = pcap_reader(fp)
        stat = extract_info(pcap)
    return stat
    
def pcap_reader(fp):
    return dpkt.pcap.Reader(fp)

def extract_info(pcap):
    """
    Precondition: pcap should have only one TCP stream containing a SSL session
    Postcondition: it return the information about SSL session in an array
    """    

    msgord=[]
    sslinfo = {'Version':0, 'C_SID': 'n', 'S_SID': 'n',  \
                 'CipherSuite': 0x0000, 'SrvCert': '', 'Records': [], 'Complete': 'n'} 

    for ts, frame in pcap:
        eth = dpkt.ethernet.Ethernet(frame)
        # ignore if not IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        # ignore if not TCP packet
        ip = eth.data
        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        # ignore if not SSL packet (only default 443)
        tcp = ip.data
        if tcp.dport != 443 and tcp.sport != 443:
            continue

        if len(tcp.data) <= 0:
            continue

        #TLS_HANDSHAKE:
        if ord(tcp.data[0]) != 22 and ord(tcp.data[0]) != 20 and ord(tcp.data[0]) != 21:
            continue

        records = []
        try:
            records, bytes_used = dpkt.ssl.TLSMultiFactory(tcp.data)
        except dpkt.ssl.SSL3Exception, e:
            continue
        except dpkt.dpkt.NeedData, e:
            continue

        if len(records) <= 0:
            continue

        for record in records:


            if record.type == 20 or record.type == 21:
                msgord.append(record.type)
                msgord.append(0)
                continue
            
            # We mainly focus on TLSHandshake
            if record.type != 22:
                #print "Record: %d" % record.type
                continue;    

            if len(record.data) == 0:
                continue
            #print "Record length: %x" % record.length

            hdtype = ord(record.data[0])

            msgord.append(record.type)
            msgord.append(hdtype)

            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
            except dpkt.ssl.SSL3Exception, e:
                continue
            except dpkt.dpkt.NeedData, e:
                continue
 
            hd = handshake.data
            #print "Handshake Protocol: 0x%02x 0x%02x" % (record.type, hdtype)
            if hdtype == 1:
                if not isinstance(hd, dpkt.ssl.TLSClientHello):
                    continue
                # Use version from client Hello for now
                sslinfo['Version'] = '%04x' % record.version    
                if  len(hd.session_id) > 0:
                    sslinfo['C_SID'] = 'y'
            elif hdtype == 2: 
                if not isinstance(hd, dpkt.ssl.TLSServerHello):
                    continue
                if  len(hd.session_id) > 0:
                    sslinfo['S_SID'] = 'y'
                sslinfo['CipherSuite'] = ('%04x' % hd.cipher_suite)
            elif hdtype == 11:  # TLSCertificate
                if not isinstance(hd, dpkt.ssl.TLSCertificate):
                    continue

                certs=[]
                for i in range(len(hd.certs)):
                       cert={}
                       cert['keytype'] = hd.certs[i].get_pubkey().type()
                       cert['Keybits'] = hd.certs[i].get_pubkey().bits()
                       cert['Signalg'] = hd.certs[i].get_signature_algorithm()
                       certs.append(cert)
                sslinfo['SrvCert'] = certs
            elif hdtype == 12:  # TLSServerkex
                if not isinstance(hd, dpkt.ssl.TLSServerKeyExchange):
                    continue

                dhsp = dpkt.ssl.getDHEServerParams(hd.data, record.version, dpkt.ssl.TLS_KEX_DHE)
                sslinfo['srv_kex'] = ['%d'% dhsp.p_len, '%d'% dhsp.g_len, '%d' % dhsp.pubkey_len,'%d'% dhsp.signature_len]
            elif hdtype == 14: # ServerHelloDone 
                sslinfo['Complete'] = 'y'
                continue;
            else:
                #print "Unknown Handshake Protocol: %d" % hdtype
                pass

    sslinfo['Records'] = msgord    
    return sslinfo

def main(argv):
    if len(argv) != 2:
        print "SSL information extractor:"
        print "    Usage: PROG <PCAP file>"    
        print ""
        sys.exit(1)
    
    import glob
    files = glob.glob(argv[1]+"/*.pcap")
    print files
    stats=[]
    for f in files:
        st = pcap_extractor(f)
        stats.append(st)
    pickle.dump(stats, open('sslinfo.dump', 'wb'))
    print "----------------"
    reader=pickle.load(open('sslinfo.dump', 'rb'))
    print reader

if __name__ == "__main__":
    main(sys.argv)
