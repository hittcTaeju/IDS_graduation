# analyzer.py
# -*- coding: utf-8 -*-
# ! /usr/bin/env python3

"""
This module defines an Analyzer class to analyze network packets, check for rule-based
intrusions, and log findings to a file.
"""

from scapy.all import Ether
from signature import Signature
from rules import load_rules


class Analyzer:
    def __init__(self, log_file, rule_path: str, show_non_intrusive: bool = False):
        self.log_file = log_file
        self.rule_path = rule_path
        self.show_non_intrusive = show_non_intrusive
        try:
            self.rules = load_rules(self.rule_path)
            print('[*] Parsed rules successfully.')
        except ValueError as err:
            exit(f"[@] Error loading rules: {err}")

    def analyze(self, packet_data):
        packet = Ether(packet_data)
        summary = packet.summary()
        try:
            packet_signature = Signature(packet)
        except ValueError as err:
            print(f"[@] Error creating signature: {err} - Packet summary: {summary}")
            return

        for rule in self.rules:
            if packet_signature == rule:
                msg = f"{rule.__repr__()} ~> {summary}"
                print(f"[!!] Intrusion detected: {msg}")
                self.log_file.write(msg + '\n')
                self.log_file.flush()
                return True

        if self.show_non_intrusive:
            print(f"[=] Non-intrusive packet: {summary}")

        return False
