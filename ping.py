from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, ICMP, UDP
from scapy.layers.l2 import Ether

import timedelta

def send_ping_request(domain_name):
    """
    the function recognize the choice and act as it need, retuens nothing
    :param domain_name: the domain that we want to acsses
    :type: string
    :return: the time of the prosses and the reply
    :rtype: tuple
    """
    #creating the ping request
    ping_req = IP(dst=domain_name)/ICMP()

    #start time
    start_time = time.time()

    #save the reply of the server
    reply = sr1(ping_req, verbose=0)

    #end time
    end_time = time.time()

    return (str(round((end_time-start_time) * 1000)), reply)

def ping():
    NUMBER_OF_REQUEST = 3
    print("> python ping.py")
    domain_name = input("Insert domain name: ")

    #save the reply and the time to varibles
    time, reply = send_ping_request(domain_name)

    #save to ip of the src of the reply - the ip of the domain
    ip_of_web = reply[IP].src

    print("Reply from " + ip_of_web + ":time=" + time + "ms")

    for i in range(NUMBER_OF_REQUEST - 1):
        time, reply = send_ping_request(domain_name)
        print("Reply from " + ip_of_web + ":time=" + time + "ms")


def main():
    ping()

if __name__ == "__main__":
    main()
