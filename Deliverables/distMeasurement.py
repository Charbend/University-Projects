#Drew Heald EECS 325 Project 2
#A lot of this is snippets from the internet
import socket
import io
import struct
import sys
import time
import requests

#Main is original code, just opens file containing websites to target, runs the trace function on each url
def main():
    f = open("websites", "r")
    for x in f:
        trace(x.rstrip())
    f.close()

#Internet snippet, creates and returns a raw UDP socket for sending packets, sets the ttl on those packets to be passed param
def create_sender(ttl):
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    return send_socket

#Internet snippet, creates a raw ICMP socket for receiving the ICMP messages, sets a timeout on the socket so it doesn't wait forever to receive a packet
def create_receiver():
    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    recv_socket.bind(("", 0))
    timeout = struct.pack("ll", 5, 0)
    recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
    return recv_socket

#Internet snippet, is used to parse the ICMP/IP/UDP headers in the received data, and repackage them as a dictionary for ease of access
def header2dict(names, struct_format, data):
    """ unpack the raw received IP and ICMP header informations to a dict """
    unpacked_data = struct.unpack(struct_format, data)
    return dict(zip(names, unpacked_data))

#Mostly written by me, based on internet snippets. Creates the sockets for sending and receiving, sends our packet to the url given by params (tries 3 times), then parses the data received to find the stats, and prints it
def trace(url):
    dest_addr = socket.gethostbyname(url)
    port = 33434
    ttl = 100
    
    #Create sockets
    send = create_sender(ttl)
    recv = create_receiver()
    
    #Build packet
    disclaimer = "measurement for class project, questions to student dsh108@case.edu or professor mxr136@case.edu"
    payload = bytes(disclaimer + 'a'*(1472-len(disclaimer)), 'ascii')
    send.sendto(payload, (dest_addr, port))

    recv_addr = None
    recv_name = None
    port_from_packet = None
    recv_data = None
    
    #Sending packet (3 tries)
    finished = False
    tries = 3
    while not finished and tries > 0:
        try:
            recv_data, recv_addr = recv.recvfrom(1500)
            finished = True
            recv_addr = recv_addr[0]
            port_from_packet = struct.unpack("!H", recv_data[50:52])[0]
            try:
                recv_name = socket.gethostbyaddr(recv_addr)[0]
            except socket.error:
                recv_name = recv_addr
        except socket.error as err: #Packet not received
            tries -= 1
            ttl *= 2
            sys.stdout.write("* ")

    #Open file to record measurements
    out = open("measurements", "a+")
    
    #if the ICMP packet was received, parse the headers from the probe we sent out, to make sure the message received was for the message we sent out
    if (recv_data != None):
        #Get data from ICMP packet
        probe_ip_header = header2dict(
            names=[
                  "version", "type", "length", "id", "flags", "ttl", "protocol",
                  "checksum", "src_ip", "dest_ip"
                  ],
            struct_format="!BBHHHBBHII", data=recv_data[28:48]
        )
        probe_ip_dest = socket.inet_ntoa(struct.pack("!I", probe_ip_header["dest_ip"]))

        resttl = probe_ip_header["ttl"]

        ipmatch = False
        portmatch = False
        
        t1 = time.time() 
      
        r = requests.get("https://" + url) 
      
        # time when acknowledgement of signal  
        # is received 
        t2 = time.time() 
      
        # total time taken 
        tim = str(t2-t1) 
        
        #determine what to print
        if (recv_addr == dest_addr):
            ipmatch = True
        if (port_from_packet == port):
            portmatch = True
        if (ipmatch or portmatch):
            testMsg = "url {}, recv_addr: {}, recv_name: {}, port from packet: {}, hops: {}, RTT: {}s\n".format(url, recv_addr, recv_name, port_from_packet, ttl-resttl, tim)
            sys.stdout.write(testMsg)
            out.write(testMsg)
            if (ipmatch):
                sys.stdout.write("matched by IP\n")
                out.write("matched by IP\n")
            if (portmatch):
                sys.stdout.write("matched by port\n")
                out.write("matched by port\n")
    else:
        errMsg = ("url {} did not send data\n").format(url)
        sys.stdout.write(errMsg)
        out.write(errMsg)
    
    send.close()
    recv.close()
    
if __name__ == "__main__":
    main()
