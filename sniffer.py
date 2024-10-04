# sniffer.py
# -*- coding: utf-8 -*-
#! /usr/bin/env python3

from scapy.all import conf, sniff, wrpcap, ETH_P_ALL
from scapy.packet import Packet

"""
This module defines a packet Sniffer class to capture network packets on a specified 
network interface and save them to a pcap file. It uses Scapy for packet sniffing and analysis.
"""

class Sniffer:
    def __init__(self, interface: str, log_name: str):
        self.interface = interface
        self.log_name = log_name

    def capture_packets(self):
        try:
            self.socket = conf.L2listen(type=ETH_P_ALL, iface=self.interface)
        except PermissionError:
            exit(f"[@] No permissions to listen on {self.interface}")

        # 패킷을 캡처하고 yield를 사용하여 하나씩 반환
        for packet in sniff(opened_socket=self.socket):
            yield packet
            wrpcap(f'logs/{self.log_name}.pcap', [packet], append=True)
