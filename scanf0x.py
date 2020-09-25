#! usr/bin/env python3
import sys
import socket
import scapy.all as scapy
from datetime import datetime
import os
os.system("sudo pip install pyfiglet")
class network:
    def discover(ip):
        os.system("pyfiglet -f big SCANFoX --color=BLUE")
        os.system("echo '\e[94m SCANFoX 1.0 \n Coded by Saif Wedyan \n Network security engineer \e[39m'")
        os.system("echo '\e[5m+\e[25m----------------------------------------------------------------\e[5m+\e[25m'")
        print("  IP Address\t\tMac Address\t\tOS")
        os.system("echo '\e[5m+\e[25m----------------------------------------------------------------\e[5m+\e[25m'")
        who_is = scapy.ARP(pdst = ip)
        broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
        sender = broadcast/who_is
        result = scapy.srp(sender, timeout = 1.5, verbose = False)[0]
        for i in result:
            print("  " + i[1].psrc + "\t\t" + i[1].hwsrc)
    def port_scanner(host):
        try:
                IP = socket.gethostbyname(host)
                print("+" + "-"*63)
                os.system("pyfiglet -f big SCANFoX --color=YELLOW")
                os.system("echo '\e[33m SCANFoX 1.0 \n Coded by Saif Wedyan \n Network security engineer \e[39m'")
                os.system("echo '\e[5m+\e[25m----------------------------------------------------------------\e[5m+\e[25m'")
                print(" Start scaning for ",IP,"at",datetime.now())
                os.system("echo '\e[5m+\e[25m----------------------------------------------------------------\e[5m+\e[25m'")
                print("Port\tStatus\tType\tService")
                print("")
                top_TCP_ports=[7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,843,873,990,993,995,1025,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5222,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49157]
                top_UDP_ports=[7,9,17,19,49,53,67,69,88,111,120,123,135,136,137,138,139,158,161,162,177,427,445,497,500,514,515,518,520,593,623,626,631,996,999,1022,1023,1025,1030,1433,1434,1645,1646,1701,1718,1719,1812,1813,1900,2000,2048,2049,2222,2223,3283,3456,3703,4444,4500,5000,5060,5353,5632,9200,10000,17185,20031,30718,31337,32768,32769,32771,32815,33281,49152,49153,49154,49156,49181,49182,49185,49186,49188,49190,49194,49200,49201,65024]
                for port in top_TCP_ports:
                    type = "tcp"
                    socket.setdefaulttimeout(1)
                    soc  = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
                    con = soc.connect_ex((IP,port))
                    if con == 0:
                        if port>=10 and port<100:
                            print(port,"\t","Open","\t","TCP","\t",socket.getservbyport(port,type))
                        if port>=100 and port<1000:
                            print(port,"\t","Open","\t","TCP","\t",socket.getservbyport(port,type))
                        if port>=1000 and port<10000:
                            print(port,"\t","Open","\t","TCP","\t",socket.getservbyport(port,type))
                        if port>=10000 and port<65536:
                            print(port,"\t","Open","\t","TCP","\t",socket.getservbyport(port,type))

                        soc.close()
                for portx in top_UDP_ports:
                    type = "udp"
                    socket.setdefaulttimeout(1)
                    sock  = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
                    conn = sock.connect_ex((IP,portx))
                    if conn == 0:
                        if portx>=10 and portx<100:
                            print(portx,"\t","Open","\t","UDP","\t",socket.getservbyport(portx,type))
                        if portx>=100 and portx<1000:
                            print(portx,"\t","Open","\t","UDP","\t",socket.getservbyport(portx,type))
                        if portx>=1000 and portx<10000:
                            print(portx,"\t","Open","\t","UDP","\t",socket.getservbyport(portx,type))
                        if portx>=10000 and portx<65536:
                            print(portx,"\t","Open","\t","UDP","\t", socket.getservbyport(portx,type))

                        soc.close()
        except KeyboardInterrupt:
            sys.exit()
        except socket.error:
            print("Can not connect to server!")
            sys.exit()
if len(sys.argv) == 2 and (sys.argv[1] == "--help" or sys.argv[1] == "-h"):
    print("\tscanf0x 1.0\n\t[*] Usage: python3 scanf0x.py [option] <target>\n\t[*] options:\n\t-d, --discover: to discover devices in your network on range of IPs\n\t-p, --ports: to get you open ports in host\n\t[*] example: sudo python3 scanf0x --ports www.site.com")
elif len(sys.argv) == 3 and (sys.argv[1] == "--ports" or sys.argv[1] == "-p"):
    network.port_scanner(sys.argv[2])
elif len(sys.argv) == 3 and (sys.argv[1] == "--discover" or sys.argv[1] == "-d"):
    network.discover(sys.argv[2])
