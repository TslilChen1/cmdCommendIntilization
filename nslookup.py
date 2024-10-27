from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, ICMP, UDP
from scapy.layers.l2 import Ether

def nslookup():
    """
    the function gets a domain to search its ip and send a dns request to google server
    """
    GOOGLE_ADRESS = '8.8.8.8'
    GOOGLE_PORT = 53

    print("> python nslookup.py")
    domain_name = input("Insert domain name: ")

    #creating the DNS request
    dns_req = IP(dst=GOOGLE_ADRESS)/UDP(dport=GOOGLE_PORT)/DNS(rd=1, qd=DNSQR(qname=domain_name))

    #save the answer from server
    answer = sr1(dns_req, verbose=0)

    adress = (answer[DNS].summary().encode())[9:-2]
    print(adress.decode('utf-8'))


def main():
    nslookup()

if __name__ == "__main__":
    main()
