# main.py
# -*- coding: utf-8 -*-
# ! /usr/bin/env python3

from os import makedirs, path
from sys import argv, exit
from time import sleep, time
from sniffer import Sniffer
from analyzer import Analyzer

"""
Intrusion Detection System (IDS) implemented in Python.
"""


def print_banner() -> None:
    banner = '''
     █████╗  ██████╗███████╗██╗         ██╗██████╗ ███████╗
    ██╔══██╗██╔════╝██╔════╝██║         ██║██╔══██╗██╔════╝
    ███████║██║     ███████╗██║         ██║██║  ██║███████╗
    ██╔══██║██║     ╚════██║██║         ██║██║  ██║╚════██║
    ██║  ██║╚██████╗███████║███████╗    ██║██████╔╝███████║
    ╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝    ╚═╝╚═════╝ ╚══════╝
    '''
    print(banner)


def main() -> None:
    print_banner()

    if len(argv) < 2:
        exit("[@] No interface was passed. Usage: main.py <INTERFACE> [RULE_PATH]")

    interface = argv[1]
    rule_path = argv[2] if len(argv) > 2 else 'default.rules'

    if not path.exists('logs'):
        makedirs('logs')

    print(f"[*] Loading {rule_path}")

    timestamp = str(int(time()))
    log_file_path = path.join('logs', f"{timestamp}.log")

    with open(log_file_path, "w") as log_file:
        sniffer = Sniffer(interface, timestamp)
        analyzer = Analyzer(log_file, rule_path)

        print('[*] Start sniffing and analyzing')

        # Sniffer에서 패킷을 읽으면서 동시에 Analyzer로 분석
        for packet in sniffer.capture_packets():
            analyzer.analyze(packet)

        print('[*] Stopping IDS')


if __name__ == '__main__':
    main()
