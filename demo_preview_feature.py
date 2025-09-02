#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据包预览功能演示脚本
展示预览列表和详细信息查看功能
"""

import os
import sys
import time

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def demo_tcp_preview():
    """演示TCP数据包预览"""
    print("演示: TCP数据包预览")
    print("-" * 30)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        # 创建GUI实例
        app = PcapGeneratorGUI()
        
        # 设置为TCP高级模式
        app.protocol_var.set("TCP")
        app.data_mode_var.set("高级模式")
        
        # 清空并添加多个数据帧
        app.clear_data_frames()
        
        # HTTP请求
        app.add_data_frame()
        app.data_frames[0]['direction'].set("客户端→服务器")
        app.data_frames[0]['data'].set("GET /api/users HTTP/1.1\\r\\nHost: api.example.com\\r\\n\\r\\n")
        app.data_frames[0]['format'].set("UTF-8")
        
        # HTTP响应
        app.add_data_frame()
        app.data_frames[1]['direction'].set("服务器→客户端")
        app.data_frames[1]['data'].set("HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n[{\"id\":1,\"name\":\"Alice\"}]")
        app.data_frames[1]['format'].set("UTF-8")
        
        # 客户端确认
        app.add_data_frame()
        app.data_frames[2]['direction'].set("客户端→服务器")
        app.data_frames[2]['data'].set("POST /api/confirm HTTP/1.1\\r\\nHost: api.example.com\\r\\n\\r\\n{\"received\":true}")
        app.data_frames[2]['format'].set("UTF-8")
        
        # 设置网络参数
        app.max_frame_size_var.set("1460")
        
        # 创建基础网络层
        generator = PacketGenerator()
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 生成数据包
        packets = app.generate_advanced_tcp_packets(eth_frame, ip_layer, 12345, 80, 1460)
        app.packet_generator.packets = packets
        
        # 更新预览
        app.update_packet_preview()
        
        print(f"生成了 {len(packets)} 个TCP数据包")
        print("预览列表显示:")
        
        # 显示预览信息
        for i, child in enumerate(app.packet_tree.get_children()):
            item = app.packet_tree.item(child)
            values = item['values']
            print(f"  {values[0]:2d}. {values[1]:4s} {values[2]:25s} -> {values[3]:25s} [{values[4]:3s}] {values[5]}")
        
        # 保存演示文件
        generator.packets = packets
        filename = "demo_tcp_preview.pcap"
        generator.save_to_pcap(filename)
        print(f"\n✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ TCP预览演示失败: {e}")
        return False

def demo_udp_preview():
    """演示UDP数据包预览"""
    print("\n演示: UDP数据包预览")
    print("-" * 30)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        app = PcapGeneratorGUI()
        
        # 设置为UDP高级模式
        app.protocol_var.set("UDP")
        app.udp_data_mode_var.set("高级模式")
        
        # 清空并添加UDP数据帧
        app.clear_udp_data_frames()
        
        # DNS查询
        app.add_udp_data_frame()
        app.udp_data_frames[0]['direction'].set("客户端→服务器")
        app.udp_data_frames[0]['data'].set("DNS Query: www.example.com A?")
        app.udp_data_frames[0]['format'].set("UTF-8")
        
        # DNS响应
        app.add_udp_data_frame()
        app.udp_data_frames[1]['direction'].set("服务器→客户端")
        app.udp_data_frames[1]['data'].set("DNS Response: www.example.com A 93.184.216.34")
        app.udp_data_frames[1]['format'].set("UTF-8")
        
        # DHCP发现
        app.add_udp_data_frame()
        app.udp_data_frames[2]['direction'].set("客户端→服务器")
        app.udp_data_frames[2]['data'].set("DHCP Discover: Client requesting IP address")
        app.udp_data_frames[2]['format'].set("UTF-8")
        
        # 十六进制数据
        app.add_udp_data_frame()
        app.udp_data_frames[3]['direction'].set("服务器→客户端")
        app.udp_data_frames[3]['data'].set("01:02:03:04:05:06:07:08:09:0A")
        app.udp_data_frames[3]['format'].set("十六进制")
        
        # 创建基础网络层
        generator = PacketGenerator()
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.1")
        
        # 生成UDP包
        packets = app.generate_advanced_udp_packets_new(eth_frame, ip_layer, 12345, 53)
        app.packet_generator.packets = packets
        
        # 更新预览
        app.update_packet_preview()
        
        print(f"生成了 {len(packets)} 个UDP数据包")
        print("预览列表显示:")
        
        # 显示预览信息
        for i, child in enumerate(app.packet_tree.get_children()):
            item = app.packet_tree.item(child)
            values = item['values']
            print(f"  {values[0]:2d}. {values[1]:4s} {values[2]:25s} -> {values[3]:25s} [{values[4]:3s}] {values[5]}")
        
        # 保存演示文件
        generator.packets = packets
        filename = "demo_udp_preview.pcap"
        generator.save_to_pcap(filename)
        print(f"\n✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ UDP预览演示失败: {e}")
        return False

def demo_mixed_protocol_preview():
    """演示混合协议预览"""
    print("\n演示: 混合协议预览")
    print("-" * 30)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        from scapy.all import Ether, IP, TCP, UDP, IPv6
        
        app = PcapGeneratorGUI()
        
        # 手动创建各种类型的数据包
        packets = []
        
        # TCP SYN
        tcp_syn = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                  IP(src="192.168.1.100", dst="192.168.1.200") / \
                  TCP(sport=12345, dport=80, flags="S", seq=1000)
        packets.append(tcp_syn)
        
        # TCP SYN-ACK
        tcp_syn_ack = Ether(src="AA:BB:CC:DD:EE:FF", dst="00:11:22:33:44:55") / \
                      IP(src="192.168.1.200", dst="192.168.1.100") / \
                      TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
        packets.append(tcp_syn_ack)
        
        # TCP ACK
        tcp_ack = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                  IP(src="192.168.1.100", dst="192.168.1.200") / \
                  TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001)
        packets.append(tcp_ack)
        
        # TCP数据包
        tcp_data = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                   IP(src="192.168.1.100", dst="192.168.1.200") / \
                   TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001) / \
                   b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        packets.append(tcp_data)
        
        # UDP DNS查询
        udp_dns = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                  IP(src="192.168.1.100", dst="8.8.8.8") / \
                  UDP(sport=12345, dport=53) / b"DNS Query"
        packets.append(udp_dns)
        
        # IPv6 UDP包
        ipv6_udp = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                   IPv6(src="2001:db8::1", dst="2001:db8::2") / \
                   UDP(sport=12345, dport=53) / b"IPv6 DNS Query"
        packets.append(ipv6_udp)
        
        # 设置到生成器
        app.packet_generator.packets = packets
        
        # 更新预览
        app.update_packet_preview()
        
        print(f"生成了 {len(packets)} 个混合协议数据包")
        print("预览列表显示:")
        
        # 显示预览信息
        for i, child in enumerate(app.packet_tree.get_children()):
            item = app.packet_tree.item(child)
            values = item['values']
            print(f"  {values[0]:2d}. {values[1]:4s} {values[2]:35s} -> {values[3]:35s} [{values[4]:3s}] {values[5]}")
        
        # 保存演示文件
        generator = PacketGenerator()
        generator.packets = packets
        filename = "demo_mixed_preview.pcap"
        generator.save_to_pcap(filename)
        print(f"\n✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 混合协议预览演示失败: {e}")
        return False

def demo_packet_analysis():
    """演示数据包分析功能"""
    print("\n演示: 数据包分析功能")
    print("-" * 30)
    
    try:
        from gui.main_window import PcapGeneratorGUI
        from scapy.all import Ether, IP, TCP, UDP
        
        app = PcapGeneratorGUI()
        
        # 创建各种测试包
        test_packets = [
            # TCP SYN
            Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
            IP(src="192.168.1.100", dst="192.168.1.200") / \
            TCP(sport=12345, dport=80, flags="S", seq=1000),
            
            # TCP PSH-ACK with data
            Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
            IP(src="192.168.1.100", dst="192.168.1.200") / \
            TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001) / \
            b"Hello World",
            
            # UDP with data
            Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
            IP(src="192.168.1.100", dst="8.8.8.8") / \
            UDP(sport=12345, dport=53) / b"DNS Query Data"
        ]
        
        print("数据包分析结果:")
        for i, packet in enumerate(test_packets, 1):
            info = app.analyze_packet(packet)
            print(f"  包 {i}:")
            print(f"    协议: {info['protocol']}")
            print(f"    源地址: {info['src_addr']}")
            print(f"    目标地址: {info['dst_addr']}")
            print(f"    长度: {info['length']} 字节")
            print(f"    摘要: {info['summary']}")
            print()
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 数据包分析演示失败: {e}")
        return False

def main():
    """主演示函数"""
    print("PCAP生成工具 - 数据包预览功能演示")
    print("=" * 60)
    print("本演示展示数据包预览列表和详细信息查看功能")
    print("生成的PCAP文件可以用Wireshark打开对比查看")
    print()
    
    demos = [
        ("TCP数据包预览", demo_tcp_preview),
        ("UDP数据包预览", demo_udp_preview),
        ("混合协议预览", demo_mixed_protocol_preview),
        ("数据包分析功能", demo_packet_analysis)
    ]
    
    success_count = 0
    
    for demo_name, demo_func in demos:
        if demo_func():
            success_count += 1
        else:
            print(f"演示 '{demo_name}' 失败")
    
    print("\n" + "=" * 60)
    print(f"演示完成: {success_count}/{len(demos)} 成功")
    
    if success_count == len(demos):
        print("🎉 所有数据包预览演示成功完成!")
        print("\n生成的文件:")
        demo_files = [
            "demo_tcp_preview.pcap",
            "demo_udp_preview.pcap",
            "demo_mixed_preview.pcap"
        ]
        for filename in demo_files:
            if os.path.exists(filename):
                print(f"  - {filename}")
        print("\n可以用Wireshark打开这些文件查看详细内容")
        print("\n预览功能特点:")
        print("- 实时显示生成的数据包列表")
        print("- 显示序号、协议、源/目标地址、长度、摘要")
        print("- 支持TCP/UDP协议智能分析")
        print("- TCP标志位识别（SYN、ACK、PSH等）")
        print("- 双击数据包查看详细信息和十六进制转储")
        print("- 自动更新预览列表")
        print("- 支持IPv4和IPv6协议")
    else:
        print("❌ 部分演示失败")

if __name__ == "__main__":
    main()
    input("\n按回车键退出...")
