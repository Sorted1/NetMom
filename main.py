import argparse
import time
from scapy.all import *

def capture_packets(interface, threshold, output_file, ddos_file):
    print(f"Sniffing on interface {interface}...")

    # Define the threshold of packets per second to trigger DDoS detection
    packet_threshold = threshold
    packet_count = 0

    # Initialize the packet list and the start time
    packet_list = []
    start_time = 0

    # Define the packet capture filter
    filter = "ip"

    # Define the packet capture callback function
    def packet_callback(packet):
        nonlocal packet_count, packet_list, start_time

        # Stop capturing packets when DDoS attack is detected
        if packet_count > packet_threshold:
            print(f"DDoS attack detected! Capturing remaining packets to {ddos_file}.")
            wrpcap(ddos_file, packet_list)

            # Continue capturing packets until packet count goes below the threshold
            while packet_count > 0:
                time.sleep(1)
                elapsed_time = time.time() - start_time
                if elapsed_time > 1:
                    print(f"{packet_count} packets captured in {elapsed_time:.2f} seconds.")
                    start_time = time.time()
                    packet_count = 0

            print("DDoS attack is over. Stopped capturing packets.")
            return

        # Add the packet to the packet list and update the packet count
        packet_list.append(packet)
        packet_count += 1

        # Print the packet count and update the start time every second
        elapsed_time = time.time() - start_time
        if elapsed_time > 1:
            print(f"{packet_count} packets captured in {elapsed_time:.2f} seconds.")
            start_time = time.time()
            packet_count = 0

    # Start the packet capture
    sniff(iface=interface, filter=filter, prn=packet_callback)

    # Write the captured packets to a pcap file
    wrpcap(output_file, packet_list)

    print(f"Packets written to {output_file}.")


if __name__ == "__main__":
    # Define the command line arguments
    parser = argparse.ArgumentParser(description="Capture packets on a network interface and detect DDoS attacks.")
    parser.add_argument("-i", "--interface", type=str, required=True, help="The network interface to capture packets on.")
    parser.add_argument("-t", "--threshold", type=int, default=1000, help="The threshold of packets per second to trigger DDoS detection.")
    parser.add_argument("-o", "--output-file", type=str, default="captured_packets.pcap", help="The name of the output pcap file to write the captured packets to.")
    parser.add_argument("-d", "--ddos-file", type=str, default="ddos_packets.pcap", help="The name of the pcap file to write the captured DDoS packets to.")
    args = parser.parse_args()

    # Call the capture_packets function with the specified arguments
    capture_packets(args.interface, args.threshold, args.output_file, args.ddos_file)
