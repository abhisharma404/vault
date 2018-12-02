from scapy.all import *

# Crafting packets


def craft_packet(dst, flag):
    ip_packet = IP(dst=dst)
    tcp_packet = TCP(sport=1024, dport=80, flags=flag)

    return ip_packet, tcp_packet


def stealth_scan():
    ip_packet, stealth_packet = craft_packet(dst='10.0.2.6', flag='S')
    stealth_resp = sr1(ip_packet/stealth_packet, timeout=2, verbose=False)

    if (str(type(stealth_resp)) == "<class 'NoneType'>"):
        print('[!] Network Error.')

    elif (stealth_resp.haslayer(TCP)):
        if (stealth_resp.getlayer(TCP).flags == 'SA'):
            send_rst = sr(ip_packet/TCP(sport=1024, dport=80, flags='R'), timeout=2, verbose=False)
            print('[+] Open')
        elif (stealth_resp.getlayer(TCP).flags == 'RA'):
            print('[-] Closed')


def xmas_scan():
    ip_packet, xmas_packet = craft_packet(dst='10.0.2.6', flag='FPU')
    xmas_resp = sr1(ip_packet/xmas_packet, timeout=2, verbose=False)

    if (str(type(xmas_resp) == "<class 'NoneType'>")):
        print('[+] Open')
    elif (xmas_resp.haslayer(TCP)):
        if (xmas_scan_resp.getlayer(TCP).flags == 'RA'):
            print('[-] Closed')
    elif (xmas_resp.haslayer(ICMP)):
        icmp_layer = xmas_resp.getayer(ICMP)
        if (int(icmp_layer.type) == 3 and int(icmp_layer.code) in [1, 2, 3, 9, 10, 13]):
            print('[!] Filtered')


def fin_scan():
    ip_packet, fin_packet = craft_packet(dst='10.0.2.6', flag='F')
    fin_scan = sr1(ip_packet/fin_packet, timeout=2, verbose=False)

    if (str(type(fin_scan)) == "<class 'NoneType'>"):
        print('[+] Open')
    elif (fin_scan.haslayer(TCP)):
        if (fin_scan.getlayer(TCP).flags == 'RA'):
            print('[-] Closed')
    elif (fin_scan.haslayer(ICMP)):
        icmp_layer = fin_scan.getlayer(ICMP)
        if (int(icmp_layer.type) == 3 and int(icmp_layer.codem) in [1, 2, 3, 9, 10, 13]):
            print('[!] Filtered')


def null_scan():
    ip_packet, null_packet = craft_packet(dst='10.0.2.6', flag="")
    null_scan = sr1(ip_packet/null_packet, timeout=2, verbose=False)

    if (str(type(null_scan)) == "<class 'NoneType'>"):
        print('[+] Open')
    elif (null_scan.haslayer(TCP)):
        if (null_scan.getlayer(TCP).flags in ['R', 'RA']):
            print('[-] Closed')
    elif (null_scan.haslayer(ICMP)):
        icmp_layer = null_scan.getlayer(ICMP)
        if (int(icmp_layer.type) == 3 and int(icmp_layer.code) in [1, 2, 3, 9, 10, 13]):
            print('[!] Filtered')


def tcp_ack_scan():
    """Used to find if a stateful firewall is present on the server or not

    A port will always respond with a RST flag whether closed or open.

    Client : ACK -> Server
    Server : RST -> Client  (Unfiltered)
    Server : ICMP -> Client (filtered)

    """

    ip_packet, tcp_ack_packet = craft_packet(dst='10.0.2.6', flag='A')
    tcp_ack_resp = sr1(ip_packet/tcp_ack_packet, timeout=2, verbose=False)

    if (str(type(tcp_ack_resp)) == "<class 'NoneType'>"):
        print('[+] Filtered')
    elif (tcp_ack_resp.haslayer(TCP)):
        if (tcp_ack_resp.getlayer(TCP).flags in ['R', 'RA']):
            print('[-] Unfiltered')
    elif (tcp_ack_resp.haslayer(ICMP)):
        icmp_layer = tcp_ack_resp.getlayer(ICMP)
        if (int(icmp_layer.type) == 3 and int(icmp_layer.code) in [1, 2, 3, 9, 10, 13]):
            print('[!] Filtered')


def tcp_window_scan():
    ip_packet, tcp_window_packet = craft_packet(dst='10.0.2.6', flag='A')
    tcp_window_resp = sr1(ip_packet/tcp_window_packet, timeout=2, verbose=False)

    if (str(type(tcp_window_resp)) == "<class 'NoneType'>"):
        print('[-] Filtered')
    elif (tcp_window_resp.haslayer(TCP)):
        if (tcp_window_resp.getlayer(TCP).flags in ['R', 'RA']):
            print('[+] Unfiltered')
            if (tcp_window_resp.getlayer(TCP).window == 0):
                print('[-] May be closed.')
            elif (tcp_window_resp.getlayer(TCP).window > 1):
                print('[+] May be opened.')
    elif (tcp_window_resp.haslayer(ICMP)):
        icmp_layer = tcp_window_resp.getlayer(ICMP)
        if (int(icmp_layer.type) == 3 and int(icmp_layer.code) in [1.2, 3, 9, 10, 13]):
            print('[-] Filtered')
