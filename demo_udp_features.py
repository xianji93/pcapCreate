#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UDP功能演示脚本
展示UDP简单模式和高级模式的使用
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def demo_udp_dns_simple():
    """演示UDP DNS查询（简单模式）"""
    print("演示: UDP DNS查询（简单模式）")
    print("-" * 40)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 设置为UDP简单模式
        app.protocol_var.set("UDP")
        app.udp_data_mode_var.set("简单模式")
        
        # 设置网络参数
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "8.8.8.8")
        
        # 设置DNS查询和响应
        app.udp_c2s_data_var.set("DNS Query: www.example.com A?")
        app.udp_s2c_data_var.set("DNS Response: www.example.com A 93.184.216.34")
        
        # 生成数据包
        packets = app.generate_simple_udp_packets(eth_frame, ip_layer, 12345, 53)
        
        print(f"生成了 {len(packets)} 个UDP数据包:")
        print("1: DNS查询包 (C2S)")
        print("2: DNS响应包 (S2C)")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_udp_dns_simple.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ UDP DNS演示失败: {e}")
        return False

def demo_udp_dhcp_simple():
    """演示UDP DHCP交互（简单模式）"""
    print("\n演示: UDP DHCP交互（简单模式）")
    print("-" * 40)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 设置为UDP简单模式
        app.protocol_var.set("UDP")
        app.udp_data_mode_var.set("简单模式")
        
        # 设置网络参数
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "FF:FF:FF:FF:FF:FF")
        ip_layer = generator.create_ip_layer(4, "0.0.0.0", "255.255.255.255")
        
        # 设置DHCP请求和响应
        dhcp_discover = "DHCP Discover: Client MAC 00:11:22:33:44:55 requesting IP"
        dhcp_offer = "DHCP Offer: Server offers IP 192.168.1.100 to client"
        
        app.udp_c2s_data_var.set(dhcp_discover)
        app.udp_s2c_data_var.set(dhcp_offer)
        
        # 生成数据包
        packets = app.generate_simple_udp_packets(eth_frame, ip_layer, 68, 67)
        
        print(f"生成了 {len(packets)} 个UDP数据包:")
        print("模拟DHCP发现和提供过程")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_udp_dhcp_simple.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ UDP DHCP演示失败: {e}")
        return False

def demo_udp_advanced_multi_packets():
    """演示UDP高级模式多包传输"""
    print("\n演示: UDP高级模式多包传输")
    print("-" * 40)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 设置为UDP高级模式
        app.protocol_var.set("UDP")
        app.udp_data_mode_var.set("高级模式")
        
        # 设置网络参数
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "10.0.0.1", "10.0.0.2")
        
        # 清空并添加多个UDP数据帧
        app.clear_udp_data_frames()
        
        # 第一个包：客户端请求
        app.add_udp_data_frame()
        app.udp_data_frames[0]['direction'].set("客户端→服务器")
        app.udp_data_frames[0]['data'].set("PING request")
        app.udp_data_frames[0]['format'].set("UTF-8")
        
        # 第二个包：服务器响应
        app.add_udp_data_frame()
        app.udp_data_frames[1]['direction'].set("服务器→客户端")
        app.udp_data_frames[1]['data'].set("PONG response")
        app.udp_data_frames[1]['format'].set("UTF-8")
        
        # 第三个包：客户端确认
        app.add_udp_data_frame()
        app.udp_data_frames[2]['direction'].set("客户端→服务器")
        app.udp_data_frames[2]['data'].set("ACK received")
        app.udp_data_frames[2]['format'].set("UTF-8")
        
        # 第四个包：十六进制数据
        app.add_udp_data_frame()
        app.udp_data_frames[3]['direction'].set("服务器→客户端")
        app.udp_data_frames[3]['data'].set("48:65:6C:6C:6F:20:57:6F:72:6C:64")  # "Hello World"
        app.udp_data_frames[3]['format'].set("十六进制")
        
        # 生成数据包
        packets = app.generate_advanced_udp_packets_new(eth_frame, ip_layer, 12345, 54321)
        
        print(f"生成了 {len(packets)} 个UDP数据包:")
        print("包含多个方向的数据传输和十六进制数据")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_udp_advanced_multi.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ UDP高级模式演示失败: {e}")
        return False

def demo_udp_syslog():
    """演示UDP Syslog传输"""
    print("\n演示: UDP Syslog传输")
    print("-" * 40)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 设置为UDP高级模式
        app.protocol_var.set("UDP")
        app.udp_data_mode_var.set("高级模式")
        
        # 设置网络参数
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 清空并添加Syslog数据
        app.clear_udp_data_frames()
        
        # Syslog消息1
        app.add_udp_data_frame()
        app.udp_data_frames[0]['direction'].set("客户端→服务器")
        app.udp_data_frames[0]['data'].set("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8")
        app.udp_data_frames[0]['format'].set("UTF-8")
        
        # Syslog消息2
        app.add_udp_data_frame()
        app.udp_data_frames[1]['direction'].set("客户端→服务器")
        app.udp_data_frames[1]['data'].set("<165>Aug 24 05:34:00 CST 1987 mymachine myproc[10]: %% It's time to make the do-nuts.  %%  Ingredients: Mix=OK, Jelly=OK # Devices: Mixer=OK, Jelly_Injector=OK, Frier=OK # Transport: Conveyer1=OK, Conveyer2=OK # %%")
        app.udp_data_frames[1]['format'].set("UTF-8")
        
        # 生成数据包
        packets = app.generate_advanced_udp_packets_new(eth_frame, ip_layer, 12345, 514)
        
        print(f"生成了 {len(packets)} 个UDP数据包:")
        print("模拟Syslog消息传输")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_udp_syslog.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ UDP Syslog演示失败: {e}")
        return False

def demo_tcp_direction_change():
    """演示TCP方向切换ACK修复"""
    print("\n演示: TCP方向切换ACK修复")
    print("-" * 40)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 设置为TCP高级模式
        app.protocol_var.set("TCP")
        app.data_mode_var.set("高级模式")
        
        # 设置网络参数
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 清空并添加方向切换的数据
        app.clear_data_frames()
        
        # C2S请求
        app.add_data_frame()
        app.data_frames[0]['direction'].set("客户端→服务器")
        app.data_frames[0]['data'].set("GET /api/data HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")
        app.data_frames[0]['format'].set("UTF-8")
        
        # S2C响应（方向切换）
        app.add_data_frame()
        app.data_frames[1]['direction'].set("服务器→客户端")
        app.data_frames[1]['data'].set("HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n{\"data\":\"value\"}")
        app.data_frames[1]['format'].set("UTF-8")
        
        # C2S确认（再次方向切换）
        app.add_data_frame()
        app.data_frames[2]['direction'].set("客户端→服务器")
        app.data_frames[2]['data'].set("POST /api/confirm HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n{\"confirmed\":true}")
        app.data_frames[2]['format'].set("UTF-8")
        
        # 设置最大帧大小
        app.max_frame_size_var.set("1460")
        
        # 生成数据包
        packets = app.generate_advanced_tcp_packets(eth_frame, ip_layer, 12345, 80, 1460)
        
        print(f"生成了 {len(packets)} 个TCP数据包:")
        print("包含方向切换时的自动ACK响应")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_tcp_direction_change.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ TCP方向切换演示失败: {e}")
        return False

def main():
    """主演示函数"""
    print("PCAP生成工具 - UDP功能和TCP修复演示")
    print("=" * 60)
    print("本演示展示UDP简单模式、高级模式和TCP方向切换ACK修复")
    print("生成的PCAP文件可以用Wireshark打开查看")
    print()
    
    demos = [
        ("UDP DNS查询（简单模式）", demo_udp_dns_simple),
        ("UDP DHCP交互（简单模式）", demo_udp_dhcp_simple),
        ("UDP高级模式多包传输", demo_udp_advanced_multi_packets),
        ("UDP Syslog传输", demo_udp_syslog),
        ("TCP方向切换ACK修复", demo_tcp_direction_change)
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
        print("🎉 所有UDP和TCP演示成功完成!")
        print("\n生成的文件:")
        demo_files = [
            "demo_udp_dns_simple.pcap",
            "demo_udp_dhcp_simple.pcap",
            "demo_udp_advanced_multi.pcap",
            "demo_udp_syslog.pcap",
            "demo_tcp_direction_change.pcap"
        ]
        for filename in demo_files:
            if os.path.exists(filename):
                print(f"  - {filename}")
        print("\n可以用Wireshark打开这些文件查看详细内容")
        print("\n新功能特点:")
        print("- UDP支持简单模式（C2S/S2C数据框）")
        print("- UDP支持高级模式（自定义帧列表）")
        print("- TCP方向切换时自动生成ACK包")
        print("- 支持UTF-8和十六进制数据格式")
        print("- 协议切换界面自动调整")
    else:
        print("❌ 部分演示失败")

if __name__ == "__main__":
    main()
    input("\n按回车键退出...")
