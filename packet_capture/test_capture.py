from scapy.all import TCP,sniff,IP,IPv6,UDP,ICMP

def packet_callback(packet):
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
    elif IPv6 in packet:
        source = packet[IPv6].src
        destination = packet[IPv6].dst
    else: return

    if TCP in packet:
        protocol = "TCP"
        ports = f"{packet[TCP].sport} -> {packet[TCP].dport}"
    elif UDP in packet:
        protocol = "UDP"
        ports = f"{packet[UDP].sport} -> {packet[UDP].dport}"
    elif ICMP in packet:
        protocol = "ICMP"
        ports = "-"
    else:
        protocol = "other"
        ports = "-"


    print(f"{source} -> {destination} | {protocol} | {ports}")

print("NetSentry packet monitor starting ....")
print("Waiting to capture 10 IP packets....")

sniff(
    prn = packet_callback,
    count = 10,
    store = False,
    lfilter = lambda packet: IP in packet or IPv6 in packet
)
print("Capture finished.")