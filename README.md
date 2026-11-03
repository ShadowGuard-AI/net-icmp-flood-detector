![Banner](banner.png)

# net-icmp-flood-detector
Detects ICMP flood attacks by monitoring the rate of incoming ICMP packets and alerting when a threshold is exceeded. Focused on basic network operations.

## Install
`git clone https://github.com/ShadowGuard-AI/net-icmp-flood-detector`

No third party dependencies: this tool uses only the Python standard library.

## Usage
`python3 main.py [--interface INTERFACE] [--threshold THRESHOLD] [--duration DURATION] [--log_file LOG_FILE]`

## Parameters
- `-h`: Show help message and exit
- `--interface`: Network interface to listen on (default: eth0)
- `--threshold`: Threshold for ICMP packets per second (default: 100)
- `--duration`: Duration to monitor in seconds (default: 60)
- `--log_file`: Log file path (default: icmp_flood_detector.log)

## Verified behavior
- `python3 main.py --help` matches the parameter list above, and `python3 -m py_compile main.py` passes.
- A live capture run is blocked in this sandbox by raw socket privileges: running against interface `lo` prints "Socket error: [Errno 1] Operation not permitted". Capture needs root or CAP_NET_RAW, and the AF_PACKET socket is Linux only. That block is stated here, not recorded as a passed capture.
- An unknown interface prints "Invalid interface" and a threshold of 0 prints "Threshold must be a positive integer."
- The rate is counted per one second window, so a burst split across two windows can stay under the threshold.

## License
See LICENSE.
