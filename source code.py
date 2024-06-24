from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print("Source IP: {}".format(ip_layer.src))
        print("Destination IP: {}".format(ip_layer.dst))

        if TCP in packet:
            tcp_layer = packet[TCP]
            print("Protocol: TCP")
            print("Source Port: {}".format(tcp_layer.sport))
            print("Destination Port: {}".format(tcp_layer.dport))
            print("Payload: {}".format(tcp_layer.payload))

        elif UDP in packet:
            udp_layer = packet[UDP]
            print("Protocol: UDP")
            print("Source Port: {}".format(udp_layer.sport))
            print("Destination Port: {}".format(udp_layer.dport))
            print("Payload: {}".format(udp_layer.payload))

        print("\n")

def main():
    # Sniff packets, applying the packet_callback function on each packet
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
