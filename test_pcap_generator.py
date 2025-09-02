#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP生成工具测试脚本
验证各项功能是否正常工作
"""

import os
import sys
import tempfile
import unittest
from scapy.all import rdpcap, Ether, IP, IPv6, TCP, UDP

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.packet_generator import PacketGenerator
from utils.validators import validate_mac_address, validate_ipv4_address, validate_ipv6_address, validate_port, normalize_mac_address

class TestValidators(unittest.TestCase):
    """测试输入验证函数"""
    
    def test_mac_address_validation(self):
        """测试MAC地址验证"""
        # 有效的MAC地址
        valid_macs = [
            "00:11:22:33:44:55",
            "AA:BB:CC:DD:EE:FF",
            "00-11-22-33-44-55",
            "aa:bb:cc:dd:ee:ff"
        ]
        for mac in valid_macs:
            self.assertTrue(validate_mac_address(mac), f"MAC地址 {mac} 应该有效")
            
        # 无效的MAC地址
        invalid_macs = [
            "00:11:22:33:44",      # 太短
            "00:11:22:33:44:55:66", # 太长
            "GG:11:22:33:44:55",   # 无效字符
            "00:11:22:33:44:ZZ",   # 无效字符
            ""                      # 空字符串
        ]
        for mac in invalid_macs:
            self.assertFalse(validate_mac_address(mac), f"MAC地址 {mac} 应该无效")
    
    def test_ipv4_validation(self):
        """测试IPv4地址验证"""
        # 有效的IPv4地址
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "255.255.255.255"
        ]
        for ip in valid_ips:
            self.assertTrue(validate_ipv4_address(ip), f"IPv4地址 {ip} 应该有效")
            
        # 无效的IPv4地址
        invalid_ips = [
            "256.1.1.1",          # 超出范围
            "192.168.1",          # 不完整
            "192.168.1.1.1",      # 太长
            "abc.def.ghi.jkl",    # 非数字
            ""                     # 空字符串
        ]
        for ip in invalid_ips:
            self.assertFalse(validate_ipv4_address(ip), f"IPv4地址 {ip} 应该无效")
    
    def test_ipv6_validation(self):
        """测试IPv6地址验证"""
        # 有效的IPv6地址
        valid_ips = [
            "2001:db8::1",
            "::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8:85a3::8a2e:370:7334"
        ]
        for ip in valid_ips:
            self.assertTrue(validate_ipv6_address(ip), f"IPv6地址 {ip} 应该有效")
            
        # 无效的IPv6地址
        invalid_ips = [
            "2001:db8::1::2",     # 双重::
            "gggg::1",            # 无效字符
            "192.168.1.1",        # IPv4格式
            ""                     # 空字符串
        ]
        for ip in invalid_ips:
            self.assertFalse(validate_ipv6_address(ip), f"IPv6地址 {ip} 应该无效")
    
    def test_port_validation(self):
        """测试端口验证"""
        # 有效端口
        valid_ports = ["1", "80", "443", "8080", "65535"]
        for port in valid_ports:
            self.assertTrue(validate_port(port), f"端口 {port} 应该有效")
            
        # 无效端口
        invalid_ports = ["0", "65536", "-1", "abc", ""]
        for port in invalid_ports:
            self.assertFalse(validate_port(port), f"端口 {port} 应该无效")
    
    def test_mac_normalization(self):
        """测试MAC地址标准化"""
        test_cases = [
            ("00:11:22:33:44:55", "00:11:22:33:44:55"),
            ("00-11-22-33-44-55", "00:11:22:33:44:55"),
            ("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF")
        ]
        for input_mac, expected in test_cases:
            result = normalize_mac_address(input_mac)
            self.assertEqual(result, expected, f"MAC地址 {input_mac} 标准化后应为 {expected}")

class TestPacketGenerator(unittest.TestCase):
    """测试数据包生成器"""
    
    def setUp(self):
        """测试前准备"""
        self.generator = PacketGenerator()
        
    def test_ethernet_frame_creation(self):
        """测试以太网帧创建"""
        src_mac = "00:11:22:33:44:55"
        dst_mac = "AA:BB:CC:DD:EE:FF"
        
        eth_frame = self.generator.create_ethernet_frame(src_mac, dst_mac)
        
        self.assertIsInstance(eth_frame, Ether)
        self.assertEqual(eth_frame.src, src_mac)
        self.assertEqual(eth_frame.dst, dst_mac)
    
    def test_ipv4_layer_creation(self):
        """测试IPv4层创建"""
        src_ip = "192.168.1.100"
        dst_ip = "192.168.1.200"
        
        ip_layer = self.generator.create_ip_layer(4, src_ip, dst_ip, ttl=64, tos=0)
        
        self.assertIsInstance(ip_layer, IP)
        self.assertEqual(ip_layer.src, src_ip)
        self.assertEqual(ip_layer.dst, dst_ip)
        self.assertEqual(ip_layer.ttl, 64)
        self.assertEqual(ip_layer.tos, 0)
    
    def test_ipv6_layer_creation(self):
        """测试IPv6层创建"""
        src_ip = "2001:db8::1"
        dst_ip = "2001:db8::2"
        
        ip_layer = self.generator.create_ip_layer(6, src_ip, dst_ip, hlim=64, tc=0)
        
        self.assertIsInstance(ip_layer, IPv6)
        self.assertEqual(ip_layer.src, src_ip)
        self.assertEqual(ip_layer.dst, dst_ip)
        self.assertEqual(ip_layer.hlim, 64)
        self.assertEqual(ip_layer.tc, 0)
    
    def test_tcp_packet_creation(self):
        """测试TCP包创建"""
        src_port = 12345
        dst_port = 80
        
        # 测试SYN包
        syn_packet = self.generator.create_tcp_syn(src_port, dst_port)
        self.assertIsInstance(syn_packet, TCP)
        self.assertEqual(syn_packet.sport, src_port)
        self.assertEqual(syn_packet.dport, dst_port)
        self.assertEqual(syn_packet.flags, 2)  # SYN flag
        
        # 测试SYN-ACK包
        syn_ack_packet = self.generator.create_tcp_syn_ack(dst_port, src_port, 1000, 2000)
        self.assertEqual(syn_ack_packet.flags, 18)  # SYN+ACK flags
        
        # 测试ACK包
        ack_packet = self.generator.create_tcp_ack(src_port, dst_port, 2000, 1001)
        self.assertEqual(ack_packet.flags, 16)  # ACK flag
    
    def test_udp_packet_creation(self):
        """测试UDP包创建"""
        src_port = 12345
        dst_port = 53
        data = b"test data"
        
        udp_packet = self.generator.create_udp_packet(src_port, dst_port, data)
        
        self.assertIsInstance(udp_packet, UDP)
        self.assertEqual(udp_packet.sport, src_port)
        self.assertEqual(udp_packet.dport, dst_port)
    
    def test_tcp_connection_generation(self):
        """测试TCP连接生成"""
        # 创建测试参数
        eth_frame = self.generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = self.generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 生成TCP连接（无数据）
        packets = self.generator.generate_tcp_connection(eth_frame, ip_layer, 12345, 80, 0)
        
        # 应该有3个包：SYN, SYN-ACK, ACK
        self.assertEqual(len(packets), 3)
        
        # 检查第一个包是SYN
        tcp_layer = packets[0][TCP]
        self.assertEqual(tcp_layer.flags, 2)  # SYN
        
        # 检查第二个包是SYN-ACK
        tcp_layer = packets[1][TCP]
        self.assertEqual(tcp_layer.flags, 18)  # SYN+ACK
        
        # 检查第三个包是ACK
        tcp_layer = packets[2][TCP]
        self.assertEqual(tcp_layer.flags, 16)  # ACK
    
    def test_pcap_file_generation(self):
        """测试PCAP文件生成"""
        # 生成一些测试包
        eth_frame = self.generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = self.generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        packets = self.generator.generate_tcp_connection(eth_frame, ip_layer, 12345, 80, 0)
        
        self.generator.packets = packets
        
        # 创建临时文件
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp_file:
            tmp_filename = tmp_file.name
        
        try:
            # 保存到PCAP文件
            packet_count = self.generator.save_to_pcap(tmp_filename)
            self.assertEqual(packet_count, len(packets))
            
            # 验证文件存在且可读
            self.assertTrue(os.path.exists(tmp_filename))
            
            # 使用scapy读取文件验证
            read_packets = rdpcap(tmp_filename)
            self.assertEqual(len(read_packets), len(packets))
            
        finally:
            # 清理临时文件
            if os.path.exists(tmp_filename):
                os.unlink(tmp_filename)

def run_tests():
    """运行所有测试"""
    print("开始运行PCAP生成工具测试...")
    print("=" * 50)
    
    # 创建测试套件
    test_suite = unittest.TestSuite()
    
    # 添加测试类
    test_suite.addTest(unittest.makeSuite(TestValidators))
    test_suite.addTest(unittest.makeSuite(TestPacketGenerator))
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # 输出结果
    print("\n" + "=" * 50)
    if result.wasSuccessful():
        print("✅ 所有测试通过!")
        return True
    else:
        print("❌ 部分测试失败!")
        print(f"失败: {len(result.failures)}, 错误: {len(result.errors)}")
        return False

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
