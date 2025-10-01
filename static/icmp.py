from scapy.all import *

trames = rdpcap("network-samples/arp.pcapng")
ICMP_types = {0: "Echo-Reply", 8: "Echo-Request"}
for trame in trames:
    try:
        trame[0][0].type
    except:
        continue
    if (trame[0][0].type) == 2048:  # trames en IPv4
        if (trame[0][1].version) == 4:  # paquets en IPv4
            if (trame[0][1].proto) == 1:  # paquets en icmp
                type = trame[0][2].type  # prend valeur de type dans ICMP
                print(trame.summary())
                print(f"ICMP: Type: {ICMP_types[type]}")
                print(f"Ethernet: MAC Source : {trame[0][0].src}")
                print(f"Ethernet: MAC Destination : {trame[0][0].dst}")
                print(f"IPv4 : IP Source : {trame[0][1].src}")
                print(f"IPv4 : IP Destination : {trame[0][1].dst}")
                print("\n")
    elif (trame[0][0].type) == 2054:  # trames en arp
        print(trame.summary())
        print(f"Ethernet: MAC Source : {trame[0][0].src}")
        print(f"Ethernet: MAC Destination : {trame[0][0].dst}")
        print(f"ARP : Sender MAC Address : {trame[0][1].hwsrc}")
        print(f"ARP : Sender IP Address : {trame[0][1].psrc}")
        print(f"ARP : Target MAC Address : {trame[0][1].hwdst}")
        print(f"ARP : Target IP Address : {trame[0][1].pdst}")
        print("\n")
