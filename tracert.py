from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, ICMP, UDP
from scapy.layers.l2 import Ether


def send_ping_request(domain_name, ttl_givven):
    """
    the function send a ping requeust with the givven ttl
    :param domain_name: thr name of the domain we want to acsses
    :type: string
    :param: ttl_givven : the ttl that i want the pong reqeust to have
    :type: int
    :return: the ip of the last station the request stopped at
    """

    #creating the ping reuest
    ping_req = IP(dst=domain_name)/ICMP()

    #changing the ttl
    ping_req[IP].ttl = ttl_givven

    #saving the reply from the server
    reply = sr1(ping_req, timeout=1, verbose=0)
    if reply and ICMP in reply:
        ip_of_web = reply[IP].src
        return str(ip_of_web)
    else:
        return "Request timed out"

def ping_request_to_get_ip(domain_name):
    ping_req = IP(dst=domain_name)/ICMP()
    reply = sr1(ping_req, timeout=1, verbose=0)

    if reply and ICMP in reply:
        ip_of_web = reply[IP].src
        return str(ip_of_web)
    else:
        return "Request timed out"

def tracert():
    """
    the function does the tracert action
    """
    print("> python tracert.py")
    domain_name = input("Insert domain name: ")
    target_ip = ping_request_to_get_ip(domain_name)
    server_ip = ""

    #min ttl
    ttl = 1

    #while we dont get to the target
    while target_ip != server_ip:

        #save each server ip
        server_ip = send_ping_request(domain_name, ttl)

        print(str(ttl) + ": " + server_ip)

        #appending 1 to ttl
        ttl += 1

    print("Trace complete.")


def main():

    tracert()

if __name__ == "__main__":
    main()
