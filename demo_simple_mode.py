#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单模式新功能演示脚本
展示C2S和S2C数据框的使用
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def demo_http_request_response():
    """演示HTTP请求响应"""
    print("演示: HTTP请求响应（简单模式）")
    print("-" * 40)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        # 创建生成器和GUI实例
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 设置为简单模式
        app.data_mode_var.set("简单模式")
        
        # 设置网络参数
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 设置HTTP请求和响应
        app.c2s_data_var.set("GET /api/users HTTP/1.1\\r\\nHost: api.example.com\\r\\nUser-Agent: PCAP-Generator\\r\\nAccept: application/json\\r\\n\\r\\n")
        app.s2c_data_var.set("HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nContent-Length: 45\\r\\n\\r\\n{\"users\":[{\"id\":1,\"name\":\"Alice\"}]}")
        app.data_size_var.set("1460")
        
        # 生成数据包
        packets = app.generate_simple_tcp_packets(eth_frame, ip_layer, 12345, 80)
        
        print(f"生成了 {len(packets)} 个数据包:")
        print("1-3: TCP三次握手")
        print("4: HTTP请求包 (C2S)")
        print("5: 服务器ACK响应")
        print("6: HTTP响应包 (S2C)")
        print("7: 客户端ACK响应")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_simple_http.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ HTTP演示失败: {e}")
        return False

def demo_api_call():
    """演示API调用"""
    print("\n演示: API调用（简单模式）")
    print("-" * 40)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 设置为简单模式
        app.data_mode_var.set("简单模式")
        
        # 设置网络参数
        eth_frame = generator.create_ethernet_frame("00:AA:BB:CC:DD:EE", "FF:EE:DD:CC:BB:AA")
        ip_layer = generator.create_ip_layer(4, "10.0.0.100", "10.0.0.200")
        
        # 设置API请求和响应
        api_request = "POST /api/login HTTP/1.1\\r\\nHost: auth.example.com\\r\\nContent-Type: application/json\\r\\nContent-Length: 45\\r\\n\\r\\n{\"username\":\"admin\",\"password\":\"secret123\"}"
        api_response = "HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nSet-Cookie: session=abc123\\r\\n\\r\\n{\"success\":true,\"token\":\"jwt_token_here\"}"
        
        app.c2s_data_var.set(api_request)
        app.s2c_data_var.set(api_response)
        app.data_size_var.set("1460")
        
        # 生成数据包
        packets = app.generate_simple_tcp_packets(eth_frame, ip_layer, 8080, 443)
        
        print(f"生成了 {len(packets)} 个数据包:")
        print("包含完整的API登录请求和响应")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_simple_api.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ API演示失败: {e}")
        return False

def demo_large_data_transfer():
    """演示大数据传输和分片"""
    print("\n演示: 大数据传输和分片（简单模式）")
    print("-" * 40)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 设置为简单模式
        app.data_mode_var.set("简单模式")
        
        # 设置网络参数
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 创建大数据（超过分片大小）
        large_request = "POST /upload HTTP/1.1\\r\\nHost: upload.example.com\\r\\nContent-Type: text/plain\\r\\nContent-Length: 2000\\r\\n\\r\\n" + "A" * 2000
        large_response = "HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n" + "B" * 1500
        
        app.c2s_data_var.set(large_request)
        app.s2c_data_var.set(large_response)
        app.data_size_var.set("800")  # 较小的分片大小
        
        # 生成数据包
        packets = app.generate_simple_tcp_packets(eth_frame, ip_layer, 12345, 80)
        
        print(f"生成了 {len(packets)} 个数据包:")
        print(f"C2S数据: {len(large_request)} 字节")
        print(f"S2C数据: {len(large_response)} 字节")
        print(f"分片大小: 800 字节")
        print("数据自动分片并生成对应的ACK包")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_simple_large.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 大数据演示失败: {e}")
        return False

def demo_one_way_communication():
    """演示单向通信"""
    print("\n演示: 单向通信（简单模式）")
    print("-" * 40)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 设置为简单模式
        app.data_mode_var.set("简单模式")
        
        # 设置网络参数
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 只设置C2S数据，S2C为空
        app.c2s_data_var.set("PING server\\r\\n")
        app.s2c_data_var.set("")  # 空响应
        app.data_size_var.set("1460")
        
        # 生成数据包
        packets = app.generate_simple_tcp_packets(eth_frame, ip_layer, 12345, 80)
        
        print(f"生成了 {len(packets)} 个数据包:")
        print("只包含C2S数据，没有S2C响应")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_simple_oneway.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 单向通信演示失败: {e}")
        return False

def demo_escape_sequences():
    """演示转义序列使用"""
    print("\n演示: 转义序列使用（简单模式）")
    print("-" * 40)
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        generator = PacketGenerator()
        app = PcapGeneratorGUI()
        
        # 设置为简单模式
        app.data_mode_var.set("简单模式")
        
        # 设置网络参数
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 使用各种转义序列
        request_with_escapes = "Line1\\r\\nLine2\\r\\nTab\\tSeparated\\tValues\\r\\nEnd"
        response_with_escapes = "Response\\r\\nWith\\r\\nMultiple\\r\\nLines\\r\\n"
        
        app.c2s_data_var.set(request_with_escapes)
        app.s2c_data_var.set(response_with_escapes)
        app.data_size_var.set("1460")
        
        # 生成数据包
        packets = app.generate_simple_tcp_packets(eth_frame, ip_layer, 12345, 80)
        
        print(f"生成了 {len(packets)} 个数据包:")
        print("包含转义序列：\\r\\n（回车换行）、\\t（制表符）")
        
        # 保存到文件
        generator.packets = packets
        filename = "demo_simple_escape.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 转义序列演示失败: {e}")
        return False

def main():
    """主演示函数"""
    print("PCAP生成工具 - 简单模式新功能演示")
    print("=" * 60)
    print("本演示展示简单模式中新增的C2S和S2C数据框功能")
    print("生成的PCAP文件可以用Wireshark打开查看")
    print()
    
    demos = [
        ("HTTP请求响应", demo_http_request_response),
        ("API调用", demo_api_call),
        ("大数据传输和分片", demo_large_data_transfer),
        ("单向通信", demo_one_way_communication),
        ("转义序列使用", demo_escape_sequences)
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
        print("🎉 所有简单模式演示成功完成!")
        print("\n生成的文件:")
        demo_files = [
            "demo_simple_http.pcap",
            "demo_simple_api.pcap", 
            "demo_simple_large.pcap",
            "demo_simple_oneway.pcap",
            "demo_simple_escape.pcap"
        ]
        for filename in demo_files:
            if os.path.exists(filename):
                print(f"  - {filename}")
        print("\n可以用Wireshark打开这些文件查看详细内容")
        print("\n简单模式特点:")
        print("- 支持C2S和S2C两个数据框")
        print("- 自动处理TCP握手和ACK响应")
        print("- 支持转义序列（\\r\\n, \\t等）")
        print("- 大数据自动分片")
        print("- 可以只填写一个方向的数据")
    else:
        print("❌ 部分演示失败")

if __name__ == "__main__":
    main()
    input("\n按回车键退出...")
