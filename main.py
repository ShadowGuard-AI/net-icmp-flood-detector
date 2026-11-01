import socket
import time
import argparse
import logging
import struct

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Detects ICMP flood attacks by monitoring the rate of incoming ICMP packets.")
    parser.add_argument("--interface", type=str, default="eth0", help="Network interface to listen on (default: eth0)")
    parser.add_argument("--threshold", type=int, default=100, help="Threshold for ICMP packets per second (default: 100)")
    parser.add_argument("--duration", type=int, default=60, help="Duration to monitor in seconds (default: 60)")
    parser.add_argument("--log_file", type=str, default="icmp_flood_detector.log", help="Log file path (default: icmp_flood_detector.log)")
    return parser.parse_args()

def is_valid_interface(interface):
    """
    Validates if the provided interface exists on the system.
    This is a basic check and might not be foolproof on all systems.
    """
    try:
        socket.if_nametoindex(interface)
        return True
    except OSError:
        return False

def analyze_icmp_packets(interface, threshold, duration):
    """
    Monitors ICMP packets on the specified interface and alerts if the threshold is exceeded.
    """
    # AF_PACKET is Linux only and opening this socket needs root or
    # CAP_NET_RAW. On an unprivileged run the socket call itself raises
    # and the error handlers below are the only output the user gets.
    try:
        # Create a raw socket to capture all packets
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))  # 3 is for all protocols
        sock.bind((interface, 0))

        packet_count = 0
        start_time = time.time()

        logging.info(f"Monitoring ICMP packets on interface {interface} for {duration} seconds with a threshold of {threshold} packets/second.")

        # recv blocks with no timeout, so the duration check only runs
        # when a packet actually arrives. On a quiet interface this loop
        # sits inside recv past the requested duration until traffic
        # shows up, and only then notices the time is up.
        while time.time() - start_time < duration:
            packet = sock.recv(65535)  # Receive a packet
            
            # Ethernet header is 14 bytes. IP header starts after that.
            # I assume plain Ethernet here: a VLAN tag adds four bytes
            # and would shift every offset below, so tagged frames are
            # misread rather than detected as ICMP.
            ip_header = packet[14:34]
            ip_header_len = (ip_header[0] & 0x0F) * 4 # Extract IHL (IP Header Length) and multiply by 4
            
            protocol = ip_header[9]

            if protocol == 1:  # ICMP protocol is 1
                packet_count += 1

            # The rate is an average over the whole current window, not
            # a count in the last second, and the window only resets
            # after this check fires. A burst that straddles a reset gets
            # split across two windows and can stay under the threshold
            # in both even though the combined rate was over it.
            elapsed_time = time.time() - start_time
            if elapsed_time >= 1:  # Check every second
                packets_per_second = packet_count / elapsed_time
                logging.debug(f"Packets per second: {packets_per_second}")

                if packets_per_second > threshold:
                    logging.warning(f"ICMP flood detected! Packets per second: {packets_per_second:.2f} (Threshold: {threshold})")
                    # Add your alerting mechanism here (e.g., send an email, log to a SIEM)
                packet_count = 0
                start_time = time.time()

    except socket.error as e:
        logging.error(f"Socket error: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        if 'sock' in locals(): # Check if sock exists before closing
            sock.close()
            logging.info("Socket closed.")

def main():
    """
    Main function to parse arguments and start the ICMP flood detection.
    """
    args = setup_argparse()

    # The file handler is added after basicConfig already set up console
    # output, so warnings from here on land in both places. Validation
    # failures below return instead of exiting non-zero, which a calling
    # script would read as success.
    # Configure logging to file
    file_handler = logging.FileHandler(args.log_file)
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logging.getLogger().addHandler(file_handler)

    # Input validation
    if not isinstance(args.threshold, int) or args.threshold <= 0:
        logging.error("Threshold must be a positive integer.")
        return

    if not isinstance(args.duration, int) or args.duration <= 0:
        logging.error("Duration must be a positive integer.")
        return
    
    if not is_valid_interface(args.interface):
        logging.error(f"Invalid interface: {args.interface}")
        return
        
    try:
        analyze_icmp_packets(args.interface, args.threshold, args.duration)
    except Exception as e:
        logging.error(f"An error occurred: {e}")

if __name__ == "__main__":
    # Usage examples:
    # 1. Basic usage: python main.py
    # 2. Specify interface, threshold, and duration: python main.py --interface wlan0 --threshold 500 --duration 120
    # 3. Specify a log file: python main.py --log_file /var/log/icmp_detector.log
    main()