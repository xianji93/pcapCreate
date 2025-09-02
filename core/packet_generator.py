#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络包生成核心模块
使用scapy库构造以太网帧、IP层和传输层数据包
"""

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
import random
import time

class PacketGenerator:
    """网络包生成器"""
    
    def __init__(self):
        self.packets = []
        self.tcp_seq = random.randint(1000, 100000)
        self.tcp_ack = 0
        
    def clear_packets(self):
        """清空已生成的包"""
        self.packets = []
        
    def create_ethernet_frame(self, src_mac, dst_mac):
        """创建以太网帧"""
        return Ether(src=src_mac, dst=dst_mac)
    
    def create_ip_layer(self, ip_version, src_ip, dst_ip, **kwargs):
        """创建IP层"""
        if ip_version == 4:
            ip_layer = IP(src=src_ip, dst=dst_ip)
            # 设置IPv4参数
            if 'ttl' in kwargs:
                ip_layer.ttl = kwargs['ttl']
            if 'tos' in kwargs:
                ip_layer.tos = kwargs['tos']
            if 'id' in kwargs:
                ip_layer.id = kwargs['id']
        else:  # IPv6
            ip_layer = IPv6(src=src_ip, dst=dst_ip)
            # 设置IPv6参数
            if 'hlim' in kwargs:
                ip_layer.hlim = kwargs['hlim']
            if 'tc' in kwargs:
                ip_layer.tc = kwargs['tc']
            if 'fl' in kwargs:
                ip_layer.fl = kwargs['fl']
                
        return ip_layer
    
    def create_tcp_syn(self, src_port, dst_port, seq=None):
        """创建TCP SYN包"""
        if seq is None:
            seq = self.tcp_seq
        return TCP(sport=src_port, dport=dst_port, flags='S', seq=seq, window=8192)
    
    def create_tcp_syn_ack(self, src_port, dst_port, seq, ack_seq):
        """创建TCP SYN-ACK包"""
        return TCP(sport=src_port, dport=dst_port, flags='SA', seq=seq, ack=ack_seq, window=8192)
    
    def create_tcp_ack(self, src_port, dst_port, seq, ack_seq):
        """创建TCP ACK包"""
        return TCP(sport=src_port, dport=dst_port, flags='A', seq=seq, ack=ack_seq, window=8192)
    
    def create_tcp_data(self, src_port, dst_port, seq, ack_seq, data, push=True):
        """创建TCP数据包"""
        flags = 'PA' if push else 'A'
        return TCP(sport=src_port, dport=dst_port, flags=flags, seq=seq, ack=ack_seq, window=8192) / data
    
    def create_udp_packet(self, src_port, dst_port, data=b''):
        """创建UDP包"""
        return UDP(sport=src_port, dport=dst_port) / data
    
    def generate_tcp_connection(self, eth_frame, ip_layer, src_port, dst_port, data_size=0):
        """生成完整的TCP连接（三次握手 + 数据传输）"""
        packets = []
        
        # 1. 客户端发送SYN
        syn_packet = eth_frame / ip_layer / self.create_tcp_syn(src_port, dst_port, self.tcp_seq)
        packets.append(syn_packet)
        
        # 2. 服务器回复SYN-ACK
        server_seq = random.randint(1000, 100000)
        eth_frame_reply = self.create_ethernet_frame(eth_frame.dst, eth_frame.src)
        ip_layer_reply = self.create_ip_layer(
            4 if isinstance(ip_layer, IP) else 6,
            ip_layer.dst, ip_layer.src
        )
        syn_ack_packet = eth_frame_reply / ip_layer_reply / self.create_tcp_syn_ack(
            dst_port, src_port, server_seq, self.tcp_seq + 1
        )
        packets.append(syn_ack_packet)
        
        # 3. 客户端发送ACK
        self.tcp_seq += 1
        self.tcp_ack = server_seq + 1
        ack_packet = eth_frame / ip_layer / self.create_tcp_ack(
            src_port, dst_port, self.tcp_seq, self.tcp_ack
        )
        packets.append(ack_packet)
        
        # 4. 如果有数据，生成数据传输包
        if data_size > 0:
            remaining_data = data_size
            while remaining_data > 0:
                # 每个数据包最大1460字节（以太网MTU 1500 - IP头20 - TCP头20）
                chunk_size = min(1460, remaining_data)
                data_payload = b'A' * chunk_size  # 使用'A'填充数据
                
                data_packet = eth_frame / ip_layer / self.create_tcp_data(
                    src_port, dst_port, self.tcp_seq, self.tcp_ack, data_payload
                )
                packets.append(data_packet)
                
                self.tcp_seq += chunk_size
                remaining_data -= chunk_size
                
                # 服务器ACK响应
                if remaining_data > 0:  # 不是最后一个包才发ACK
                    ack_response = eth_frame_reply / ip_layer_reply / self.create_tcp_ack(
                        dst_port, src_port, self.tcp_ack, self.tcp_seq
                    )
                    packets.append(ack_response)
        
        return packets
    
    def generate_udp_packets(self, eth_frame, ip_layer, src_port, dst_port, data_size=0):
        """生成UDP数据包"""
        packets = []
        
        if data_size > 0:
            remaining_data = data_size
            while remaining_data > 0:
                # UDP最大数据大小（以太网MTU 1500 - IP头20 - UDP头8）
                chunk_size = min(1472, remaining_data)
                data_payload = b'U' * chunk_size  # 使用'U'填充UDP数据
                
                udp_packet = eth_frame / ip_layer / self.create_udp_packet(
                    src_port, dst_port, data_payload
                )
                packets.append(udp_packet)
                
                remaining_data -= chunk_size
        else:
            # 空UDP包
            udp_packet = eth_frame / ip_layer / self.create_udp_packet(src_port, dst_port)
            packets.append(udp_packet)
            
        return packets
    
    def save_to_pcap(self, filename):
        """保存数据包到PCAP文件"""
        if not self.packets:
            raise ValueError("没有数据包可保存")
            
        wrpcap(filename, self.packets)
        return len(self.packets)
