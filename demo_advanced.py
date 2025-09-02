#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高级功能演示脚本
展示如何使用新的数据帧配置功能
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def demo_http_simulation():
    """演示HTTP请求响应模拟"""
    print("演示: HTTP请求响应模拟")
    print("-" * 30)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        # 创建生成器和GUI实例
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 创建基础网络层
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 清空默认数据帧并添加HTTP数据
        app.clear_data_frames()
        
        # HTTP请求
        app.add_data_frame()
        app.data_frames[0]['direction'].set("客户端→服务器")
        app.data_frames[0]['data'].set("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: PCAP-Generator\r\n\r\n")
        app.data_frames[0]['format'].set("UTF-8")
        
        # HTTP响应
        app.add_data_frame()
        app.data_frames[1]['direction'].set("服务器→客户端")
        app.data_frames[1]['data'].set("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello World!")
        app.data_frames[1]['format'].set("UTF-8")
        
        # 生成数据包
        packets = app.generate_advanced_tcp_packets(eth_frame, ip_layer, 12345, 80, 1460)
        
        print(f"生成了 {len(packets)} 个数据包:")
        print("1-3: TCP三次握手 (SYN, SYN-ACK, ACK)")
        print("4: HTTP请求包")
        print("5: 服务器ACK响应")
        print("6: HTTP响应包")
        print("7: 客户端ACK响应")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_http.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ HTTP演示失败: {e}")
        return False

def demo_hex_data():
    """演示十六进制数据传输"""
    print("\n演示: 十六进制数据传输")
    print("-" * 30)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 创建基础网络层
        eth_frame = generator.create_ethernet_frame("00:AA:BB:CC:DD:EE", "FF:EE:DD:CC:BB:AA")
        ip_layer = generator.create_ip_layer(4, "10.0.0.1", "10.0.0.2")
        
        # 清空并添加十六进制数据
        app.clear_data_frames()
        
        # 发送十六进制命令
        app.add_data_frame()
        app.data_frames[0]['direction'].set("客户端→服务器")
        app.data_frames[0]['data'].set("01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10")
        app.data_frames[0]['format'].set("十六进制")
        
        # 响应十六进制数据
        app.add_data_frame()
        app.data_frames[1]['direction'].set("服务器→客户端")
        app.data_frames[1]['data'].set("FF FE FD FC FB FA F9 F8 F7 F6 F5 F4 F3 F2 F1 F0")
        app.data_frames[1]['format'].set("十六进制")
        
        # 生成数据包
        packets = app.generate_advanced_tcp_packets(eth_frame, ip_layer, 9999, 8888, 1460)
        
        print(f"生成了 {len(packets)} 个数据包:")
        print("包含十六进制数据的双向传输")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_hex.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 十六进制演示失败: {e}")
        return False

def demo_large_data_fragmentation():
    """演示大数据自动分片"""
    print("\n演示: 大数据自动分片")
    print("-" * 30)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 创建基础网络层
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 清空并添加大数据
        app.clear_data_frames()
        
        # 创建超过最大帧大小的数据
        large_data = "A" * 3000  # 3000字节的数据
        
        app.add_data_frame()
        app.data_frames[0]['direction'].set("客户端→服务器")
        app.data_frames[0]['data'].set(large_data)
        app.data_frames[0]['format'].set("UTF-8")
        
        # 设置较小的最大帧大小来演示分片
        max_frame_size = 1000
        
        # 生成数据包
        packets = app.generate_advanced_tcp_packets(eth_frame, ip_layer, 12345, 80, max_frame_size)
        
        print(f"生成了 {len(packets)} 个数据包:")
        print("3个握手包 + 多个数据分片包 + 对应的ACK包")
        print(f"原始数据: {len(large_data)} 字节")
        print(f"最大帧大小: {max_frame_size} 字节")
        print(f"预期分片数: {(len(large_data) + max_frame_size - 1) // max_frame_size}")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_fragmentation.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 分片演示失败: {e}")
        return False

def demo_udp_advanced():
    """演示UDP高级模式"""
    print("\n演示: UDP高级模式")
    print("-" * 30)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 创建基础网络层
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "8.8.8.8")
        
        # 清空并添加DNS查询数据
        app.clear_data_frames()
        
        # DNS查询
        app.add_data_frame()
        app.data_frames[0]['direction'].set("客户端→服务器")
        app.data_frames[0]['data'].set("DNS Query: example.com")
        app.data_frames[0]['format'].set("UTF-8")
        
        # DNS响应
        app.add_data_frame()
        app.data_frames[1]['direction'].set("服务器→客户端")
        app.data_frames[1]['data'].set("DNS Response: 93.184.216.34")
        app.data_frames[1]['format'].set("UTF-8")
        
        # 生成UDP数据包
        packets = app.generate_advanced_udp_packets(eth_frame, ip_layer, 12345, 53)
        
        print(f"生成了 {len(packets)} 个UDP数据包:")
        print("包含DNS查询和响应的模拟")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_udp.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ UDP演示失败: {e}")
        return False

def main():
    """主演示函数"""
    print("PCAP生成工具 - 高级功能演示")
    print("=" * 50)
    print("本演示将展示新增的高级数据帧配置功能")
    print("生成的PCAP文件可以用Wireshark打开查看")
    print()
    
    demos = [
        ("HTTP请求响应模拟", demo_http_simulation),
        ("十六进制数据传输", demo_hex_data),
        ("大数据自动分片", demo_large_data_fragmentation),
        ("UDP高级模式", demo_udp_advanced)
    ]
    
    success_count = 0
    
    for demo_name, demo_func in demos:
        if demo_func():
            success_count += 1
        else:
            print(f"演示 '{demo_name}' 失败")
    
    print("\n" + "=" * 50)
    print(f"演示完成: {success_count}/{len(demos)} 成功")
    
    if success_count == len(demos):
        print("🎉 所有演示成功完成!")
        print("\n生成的文件:")
        for filename in ["demo_http.pcap", "demo_hex.pcap", "demo_fragmentation.pcap", "demo_udp.pcap"]:
            if os.path.exists(filename):
                print(f"  - {filename}")
        print("\n可以用Wireshark打开这些文件查看详细内容")
    else:
        print("❌ 部分演示失败")

if __name__ == "__main__":
    main()
    input("\n按回车键退出...")
