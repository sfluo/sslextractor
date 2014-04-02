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
import M2Crypto

p = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dpkt-1.8')
if p not in sys.path:
    sys.path.insert(0, p)

import dpkt

def pcap_reader(fp):
	return dpkt.pcap.Reader(fp)

def extract_info(pcap):
	"""
	Precondition: pcap should have only one TCP stream containing a SSL session
	Postcondition: it return the information about SSL session in an array
	"""	

	msgord=[]
	sslinfo = {'Version':0, 'C_SID': 'n', 'S_SID': 'n', \
				'CipherSuite': 0x0000, 'Certs': [], 'Records': []} 

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
				continue;	

			if len(record.data) == 0:
				continue

			try:
				handshake = dpkt.ssl.TLSHandshake(record.data)
			except dpkt.ssl.SSL3Exception, e:
				continue
			except dpkt.dpkt.NeedData, e:
				continue

			hdtype = ord(record.data[0])
			hd = handshake.data

			msgord.append(record.type)
			msgord.append(hdtype)
			#print "Handshake Protocol: 0x%02x 0x%02x" % (record.type, hdtype)
			if hdtype == 1:
				#if not isinstance(hd, dpkt.ssl.TLSClientHello):
				#	continue
				# Use version from client Hello for now
				sslinfo['Version'] = '%04x' % record.version	
				if  len(hd.session_id) > 0:
					sslinfo['C_SID'] = 'y'
			elif hdtype == 2: 
				#if not isinstance(hd, dpkt.ssl.TLSServerHello):
				#	continue
				if  len(hd.session_id) > 0:
					sslinfo['S_SID'] = 'y'
				sslinfo['CipherSuite'] = ('%04x' % hd.cipher_suite)
			elif hdtype == 11: 
				#if not isinstance(hd, dpkt.ssl.TLSCertificate):
				#	continue
				#m2cert = M2Crypto.X509.load_cert_der_string(hd.data)
				#pkey = m2cert.get_pubkey()
				#print dpkt.hex2dump(pkey, 256)
				#print m2cert.as_text()
				pass
			else:	
				#print "Unknown Handshake Protocol: %d" % hdtype
				pass
			 
			#print 'TLS : %x' % sh.version			

			#if sh.version == dpkt.ssl.SSL3_V:
			#elif sh.version == dpkt.ssl.TLS1_V:
			#elif sh.version == dpkt.ssl.TLS11_V:
			#elif sh.version == dpkt.ssl.TLS12_V:

			#if len(sh.session_id) > 0:
			#print 'CipherSuite=%x' % sh.cipher_suite

	sslinfo['Records'] = msgord	
	return sslinfo

def main(argv):
	if len(argv) != 2:
		print "SSL information extractor:"
		print "	Usage: PROG <PCAP file>"	
		print ""
		sys.exit(1)
	
	with open(argv[1], 'rb') as fp:
		pcap = pcap_reader(fp)
		stat = extract_info(pcap)
	
	print stat
	
if __name__ == "__main__":
	main(sys.argv)
