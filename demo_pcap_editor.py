#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP编辑功能演示脚本
展示读取PCAP文件、分层编辑和保存功能
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def create_demo_pcap_files():
    """创建演示用的PCAP文件"""
    print("创建演示用的PCAP文件...")
    
    try:
        from scapy.all import Ether, IP, IPv6, TCP, UDP, wrpcap
        
        # 创建HTTP请求响应
        http_packets = []
        
        # HTTP请求
        http_request = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                      IP(src="192.168.1.100", dst="192.168.1.200", ttl=64) / \
                      TCP(sport=12345, dport=80, flags="PA", seq=1000, ack=2000) / \
                      b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Demo-Client\r\n\r\n"
        http_packets.append(http_request)
        
        # HTTP响应
        http_response = Ether(src="AA:BB:CC:DD:EE:FF", dst="00:11:22:33:44:55") / \
                       IP(src="192.168.1.200", dst="192.168.1.100", ttl=64) / \
                       TCP(sport=80, dport=12345, flags="PA", seq=2000, ack=1100) / \
                       b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello World!"
        http_packets.append(http_response)
        
        wrpcap("demo_http.pcap", http_packets)
        print(f"✓ 创建 demo_http.pcap ({len(http_packets)} 个包)")
        
        # 创建DNS查询响应
        dns_packets = []
        
        # DNS查询
        dns_query = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                   IP(src="192.168.1.100", dst="8.8.8.8", ttl=64) / \
                   UDP(sport=12345, dport=53) / \
                   b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
        dns_packets.append(dns_query)
        
        # DNS响应
        dns_response = Ether(src="AA:BB:CC:DD:EE:FF", dst="00:11:22:33:44:55") / \
                      IP(src="8.8.8.8", dst="192.168.1.100", ttl=64) / \
                      UDP(sport=53, dport=12345) / \
                      b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22"
        dns_packets.append(dns_response)
        
        wrpcap("demo_dns.pcap", dns_packets)
        print(f"✓ 创建 demo_dns.pcap ({len(dns_packets)} 个包)")
        
        # 创建IPv6包
        ipv6_packets = []
        
        ipv6_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                     IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=64) / \
                     TCP(sport=12345, dport=80, flags="S", seq=1000) / \
                     b"IPv6 Test Data"
        ipv6_packets.append(ipv6_packet)
        
        wrpcap("demo_ipv6.pcap", ipv6_packets)
        print(f"✓ 创建 demo_ipv6.pcap ({len(ipv6_packets)} 个包)")
        
        # 创建混合协议包
        mixed_packets = []
        
        # TCP SYN
        tcp_syn = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                 IP(src="192.168.1.100", dst="192.168.1.200") / \
                 TCP(sport=12345, dport=80, flags="S", seq=1000)
        mixed_packets.append(tcp_syn)
        
        # UDP包
        udp_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                    IP(src="192.168.1.100", dst="8.8.8.8") / \
                    UDP(sport=12345, dport=53) / \
                    b"Mixed protocol test"
        mixed_packets.append(udp_packet)
        
        # 带中文数据的包
        chinese_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                        IP(src="192.168.1.100", dst="192.168.1.200") / \
                        TCP(sport=12345, dport=80, flags="PA", seq=2000, ack=1000) / \
                        "你好世界，这是中文测试数据！".encode('utf-8')
        mixed_packets.append(chinese_packet)
        
        wrpcap("demo_mixed.pcap", mixed_packets)
        print(f"✓ 创建 demo_mixed.pcap ({len(mixed_packets)} 个包)")
        
        return ["demo_http.pcap", "demo_dns.pcap", "demo_ipv6.pcap", "demo_mixed.pcap"]
        
    except Exception as e:
        print(f"✗ 创建演示文件失败: {e}")
        return []

def demo_pcap_analysis():
    """演示PCAP文件分析"""
    print("\n演示: PCAP文件分析")
    print("-" * 40)
    
    try:
        from gui.main_window import PcapGeneratorGUI
        from scapy.all import rdpcap
        
        app = PcapGeneratorGUI()
        
        # 读取HTTP演示文件
        packets = rdpcap("demo_http.pcap")
        app.packet_generator.packets = packets
        
        print(f"读取了 {len(packets)} 个数据包")
        print("数据包分析结果:")
        
        for i, packet in enumerate(packets, 1):
            info = app.analyze_packet(packet)
            print(f"  包 {i}: {info['protocol']} - {info['summary']}")
            print(f"       {info['src_addr']} -> {info['dst_addr']} ({info['length']} 字节)")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ PCAP分析演示失败: {e}")
        return False

def demo_layer_inspection():
    """演示分层检查功能"""
    print("\n演示: 分层检查功能")
    print("-" * 40)
    
    try:
        from gui.main_window import PcapGeneratorGUI
        from scapy.all import rdpcap, Ether, IP, TCP
        
        app = PcapGeneratorGUI()
        
        # 读取混合协议文件
        packets = rdpcap("demo_mixed.pcap")
        
        for i, packet in enumerate(packets, 1):
            print(f"\n包 {i} 的层次结构:")
            
            # 检查各层
            if Ether in packet:
                eth = packet[Ether]
                print(f"  以太网层: {eth.src} -> {eth.dst} (类型: 0x{eth.type:04x})")
            
            if IP in packet:
                ip = packet[IP]
                print(f"  IP层: {ip.src} -> {ip.dst} (TTL: {ip.ttl}, 协议: {ip.proto})")
            
            if TCP in packet:
                tcp = packet[TCP]
                flags = []
                if tcp.flags & 0x01: flags.append('FIN')
                if tcp.flags & 0x02: flags.append('SYN')
                if tcp.flags & 0x04: flags.append('RST')
                if tcp.flags & 0x08: flags.append('PSH')
                if tcp.flags & 0x10: flags.append('ACK')
                if tcp.flags & 0x20: flags.append('URG')
                
                print(f"  TCP层: {tcp.sport} -> {tcp.dport} (标志: {','.join(flags)}, 序列号: {tcp.seq})")
            
            # 检查应用层数据
            payload = app.get_payload_data(packet)
            if payload:
                print(f"  应用层: {len(payload)} 字节数据")
                if len(payload) <= 50:
                    try:
                        # 尝试显示为UTF-8
                        text = payload.decode('utf-8', errors='replace')
                        print(f"    内容: {repr(text)}")
                    except:
                        # 显示为十六进制
                        hex_str = payload.hex()
                        print(f"    十六进制: {hex_str}")
                else:
                    print(f"    数据过长，仅显示前20字节: {payload[:20].hex()}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 分层检查演示失败: {e}")
        return False

def demo_payload_formats():
    """演示应用层数据格式显示"""
    print("\n演示: 应用层数据格式显示")
    print("-" * 40)
    
    try:
        from gui.main_window import PcapGeneratorGUI
        import tkinter as tk
        from tkinter import ttk
        
        app = PcapGeneratorGUI()
        
        # 测试不同类型的数据
        test_data_sets = [
            ("HTTP文本", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            ("中文UTF-8", "你好世界，这是中文测试！".encode('utf-8')),
            ("二进制数据", b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"),
            ("混合数据", b"Hello\x00World\xFF\xFE\xFD")
        ]
        
        root = tk.Tk()
        root.withdraw()  # 隐藏主窗口
        
        for name, data in test_data_sets:
            print(f"\n{name} ({len(data)} 字节):")
            
            # 创建临时文本框
            text_widget = tk.Text(root)
            
            # 十六进制格式
            app.update_payload_display(text_widget, data, "十六进制")
            hex_content = text_widget.get(1.0, tk.END).strip()
            print(f"  十六进制: {hex_content[:60]}{'...' if len(hex_content) > 60 else ''}")
            
            # UTF-8格式
            app.update_payload_display(text_widget, data, "UTF-8")
            utf8_content = text_widget.get(1.0, tk.END).strip()
            print(f"  UTF-8: {repr(utf8_content[:40])}{'...' if len(utf8_content) > 40 else ''}")
            
            # ASCII格式
            app.update_payload_display(text_widget, data, "ASCII")
            ascii_content = text_widget.get(1.0, tk.END).strip()
            print(f"  ASCII: {repr(ascii_content[:40])}{'...' if len(ascii_content) > 40 else ''}")
        
        root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 数据格式演示失败: {e}")
        return False

def demo_packet_modification():
    """演示数据包修改功能"""
    print("\n演示: 数据包修改功能")
    print("-" * 40)
    
    try:
        from gui.main_window import PcapGeneratorGUI
        from scapy.all import rdpcap, wrpcap
        import tkinter as tk
        
        app = PcapGeneratorGUI()
        
        # 读取原始文件
        original_packets = rdpcap("demo_http.pcap")
        app.packet_generator.packets = original_packets.copy()
        
        print("原始数据包信息:")
        original_info = app.analyze_packet(original_packets[0])
        print(f"  {original_info['src_addr']} -> {original_info['dst_addr']}")
        
        # 模拟修改第一个包
        app.current_packet_index = tk.IntVar(value=0)
        
        # 设置修改后的字段值
        app.edit_fields = {
            'eth_0_src': tk.StringVar(value="00:AA:BB:CC:DD:EE"),  # 修改源MAC
            'eth_0_dst': tk.StringVar(value="FF:EE:DD:CC:BB:AA"),  # 修改目标MAC
            'eth_0_type': tk.StringVar(value="0x0800"),
            'ip_1_src': tk.StringVar(value="10.0.0.100"),          # 修改源IP
            'ip_1_dst': tk.StringVar(value="10.0.0.200"),          # 修改目标IP
            'ip_1_ttl': tk.StringVar(value="128"),                 # 修改TTL
            'ip_1_version': tk.StringVar(value="4"),
            'ip_1_ihl': tk.StringVar(value="5"),
            'ip_1_tos': tk.StringVar(value="0"),
            'ip_1_len': tk.StringVar(value="40"),
            'ip_1_id': tk.StringVar(value="1"),
            'ip_1_flags': tk.StringVar(value="2"),
            'ip_1_proto': tk.StringVar(value="6"),
            'tcp_2_sport': tk.StringVar(value="54321"),            # 修改源端口
            'tcp_2_dport': tk.StringVar(value="443"),              # 修改目标端口
            'tcp_2_seq': tk.StringVar(value="5000"),               # 修改序列号
            'tcp_2_ack': tk.StringVar(value="3000"),               # 修改确认号
            'tcp_2_window': tk.StringVar(value="16384"),
            'tcp_2_urgptr': tk.StringVar(value="0")
        }
        
        app.tcp_flags = {
            'tcp_2_syn': tk.BooleanVar(value=False),
            'tcp_2_ack': tk.BooleanVar(value=True),
            'tcp_2_psh': tk.BooleanVar(value=True),
            'tcp_2_fin': tk.BooleanVar(value=False),
            'tcp_2_rst': tk.BooleanVar(value=False),
            'tcp_2_urg': tk.BooleanVar(value=False)
        }
        
        # 重构数据包
        modified_packet = app.rebuild_packet(0)
        
        if modified_packet:
            app.packet_generator.packets[0] = modified_packet
            
            print("\n修改后的数据包信息:")
            modified_info = app.analyze_packet(modified_packet)
            print(f"  {modified_info['src_addr']} -> {modified_info['dst_addr']}")
            
            # 保存修改后的文件
            wrpcap("demo_http_modified.pcap", app.packet_generator.packets)
            print("✓ 修改后的数据包已保存到 demo_http_modified.pcap")
            
            # 显示修改对比
            print("\n修改对比:")
            print(f"  源MAC: {original_packets[0].src} -> {modified_packet.src}")
            print(f"  源IP: {original_packets[0][1].src} -> {modified_packet[1].src}")
            print(f"  源端口: {original_packets[0][2].sport} -> {modified_packet[2].sport}")
            print(f"  TTL: {original_packets[0][1].ttl} -> {modified_packet[1].ttl}")
        else:
            print("✗ 数据包重构失败")
            return False
        
        return True
        
    except Exception as e:
        print(f"✗ 数据包修改演示失败: {e}")
        return False

def main():
    """主演示函数"""
    print("PCAP生成工具 - PCAP读取和编辑功能演示")
    print("=" * 70)
    print("本演示展示PCAP文件读取、分层分析和编辑功能")
    print()
    
    # 创建演示文件
    demo_files = create_demo_pcap_files()
    if not demo_files:
        print("❌ 无法创建演示文件")
        return
    
    demos = [
        ("PCAP文件分析", demo_pcap_analysis),
        ("分层检查功能", demo_layer_inspection),
        ("应用层数据格式", demo_payload_formats),
        ("数据包修改功能", demo_packet_modification)
    ]
    
    success_count = 0
    
    for demo_name, demo_func in demos:
        print(f"\n{'='*20} {demo_name} {'='*20}")
        if demo_func():
            success_count += 1
        else:
            print(f"演示 '{demo_name}' 失败")
    
    print("\n" + "=" * 70)
    print(f"演示完成: {success_count}/{len(demos)} 成功")
    
    if success_count == len(demos):
        print("🎉 所有PCAP编辑演示成功完成!")
        print("\n生成的文件:")
        all_files = demo_files + ["demo_http_modified.pcap"]
        for filename in all_files:
            if os.path.exists(filename):
                print(f"  - {filename}")
        print("\n可以用Wireshark打开这些文件查看和对比")
        print("\nPCAP编辑功能特点:")
        print("- 读取标准PCAP/PCAPNG文件")
        print("- 智能分层分析（以太网、IP、TCP/UDP、应用层）")
        print("- 可视化编辑各层字段")
        print("- 多格式应用层数据显示和编辑")
        print("- 实时数据包重构和预览")
        print("- 支持IPv4/IPv6和TCP/UDP协议")
        print("- 完整的修改历史和对比功能")
    else:
        print("❌ 部分演示失败")

if __name__ == "__main__":
    main()
    input("\n按回车键退出...")
