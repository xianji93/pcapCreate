#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试UDP功能和TCP修复
验证UDP简单模式、高级模式和TCP方向切换ACK修复
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_udp_simple_mode():
    """测试UDP简单模式"""
    print("测试UDP简单模式...")
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        # 创建GUI实例
        app = PcapGeneratorGUI()
        
        # 设置为UDP简单模式
        app.protocol_var.set("UDP")
        app.udp_data_mode_var.set("简单模式")
        
        # 设置UDP数据
        app.udp_c2s_data_var.set("DNS Query: www.example.com")
        app.udp_s2c_data_var.set("DNS Response: 93.184.216.34")
        
        # 创建基础网络层
        generator = PacketGenerator()
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "8.8.8.8")
        
        # 生成UDP包
        packets = app.generate_simple_udp_packets(eth_frame, ip_layer, 12345, 53)
        
        # 验证包数量
        assert len(packets) == 2, f"UDP简单模式应该生成2个包，实际生成了{len(packets)}个"
        print(f"✓ 生成了 {len(packets)} 个UDP包")
        
        # 验证包类型
        from scapy.layers.inet import UDP
        for packet in packets:
            assert UDP in packet, "包中应该包含UDP层"
        print("✓ 所有包都包含UDP层")
        
        # 保存测试文件
        generator.packets = packets
        filename = "test_udp_simple.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ UDP简单模式测试失败: {e}")
        return False

def test_udp_advanced_mode():
    """测试UDP高级模式"""
    print("\n测试UDP高级模式...")
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        app = PcapGeneratorGUI()
        
        # 设置为UDP高级模式
        app.protocol_var.set("UDP")
        app.udp_data_mode_var.set("高级模式")
        
        # 清空默认数据帧并添加自定义数据
        app.clear_udp_data_frames()
        
        # 添加DNS查询
        app.add_udp_data_frame()
        app.udp_data_frames[0]['direction'].set("客户端→服务器")
        app.udp_data_frames[0]['data'].set("DNS Query for example.com")
        app.udp_data_frames[0]['format'].set("UTF-8")
        
        # 添加DNS响应
        app.add_udp_data_frame()
        app.udp_data_frames[1]['direction'].set("服务器→客户端")
        app.udp_data_frames[1]['data'].set("48656C6C6F")  # "Hello" in hex
        app.udp_data_frames[1]['format'].set("十六进制")
        
        # 创建基础网络层
        generator = PacketGenerator()
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "8.8.8.8")
        
        # 生成UDP包
        packets = app.generate_advanced_udp_packets_new(eth_frame, ip_layer, 12345, 53)
        
        assert len(packets) == 2, f"UDP高级模式应该生成2个包，实际生成了{len(packets)}个"
        print(f"✓ 生成了 {len(packets)} 个UDP包")
        
        # 保存测试文件
        generator.packets = packets
        filename = "test_udp_advanced.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ UDP高级模式测试失败: {e}")
        return False

def test_tcp_direction_change_ack():
    """测试TCP方向切换时的ACK修复"""
    print("\n测试TCP方向切换ACK修复...")
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        app = PcapGeneratorGUI()
        
        # 设置为TCP高级模式
        app.protocol_var.set("TCP")
        app.data_mode_var.set("高级模式")
        
        # 清空默认数据帧
        app.clear_data_frames()
        
        # 添加C2S数据
        app.add_data_frame()
        app.data_frames[0]['direction'].set("客户端→服务器")
        app.data_frames[0]['data'].set("Request from client")
        app.data_frames[0]['format'].set("UTF-8")
        
        # 添加S2C数据（方向相反）
        app.add_data_frame()
        app.data_frames[1]['direction'].set("服务器→客户端")
        app.data_frames[1]['data'].set("Response from server")
        app.data_frames[1]['format'].set("UTF-8")
        
        # 再添加C2S数据（方向再次相反）
        app.add_data_frame()
        app.data_frames[2]['direction'].set("客户端→服务器")
        app.data_frames[2]['data'].set("Another request")
        app.data_frames[2]['format'].set("UTF-8")
        
        # 设置最大帧大小
        app.max_frame_size_var.set("1460")
        
        # 创建基础网络层
        generator = PacketGenerator()
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 生成TCP包
        packets = app.generate_advanced_tcp_packets(eth_frame, ip_layer, 12345, 80, 1460)
        
        # 验证包数量（握手3个 + 数据包 + 方向切换ACK包）
        assert len(packets) >= 8, f"TCP方向切换应该生成至少8个包，实际生成了{len(packets)}个"
        print(f"✓ 生成了 {len(packets)} 个TCP包")
        
        # 验证包中包含ACK
        from scapy.layers.inet import TCP
        ack_count = 0
        for packet in packets[3:]:  # 跳过握手包
            if TCP in packet:
                tcp_layer = packet[TCP]
                if tcp_layer.flags & 0x10:  # ACK flag
                    ack_count += 1
        
        print(f"✓ 包含 {ack_count} 个ACK包（包括方向切换ACK）")
        
        # 保存测试文件
        generator.packets = packets
        filename = "test_tcp_direction_ack.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ TCP方向切换ACK测试失败: {e}")
        return False

def test_mixed_protocols():
    """测试协议切换功能"""
    print("\n测试协议切换功能...")
    
    try:
        from gui.main_window import PcapGeneratorGUI
        
        app = PcapGeneratorGUI()
        
        # 测试TCP到UDP切换
        app.protocol_var.set("TCP")
        app.on_protocol_change()
        print("✓ 切换到TCP协议")
        
        app.protocol_var.set("UDP")
        app.on_protocol_change()
        print("✓ 切换到UDP协议")
        
        # 测试UDP模式切换
        app.udp_data_mode_var.set("简单模式")
        app.on_udp_data_mode_change()
        print("✓ UDP简单模式切换")
        
        app.udp_data_mode_var.set("高级模式")
        app.on_udp_data_mode_change()
        print("✓ UDP高级模式切换")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 协议切换测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("PCAP生成工具 - UDP功能和TCP修复测试")
    print("=" * 50)
    
    tests = [
        ("UDP简单模式", test_udp_simple_mode),
        ("UDP高级模式", test_udp_advanced_mode),
        ("TCP方向切换ACK修复", test_tcp_direction_change_ack),
        ("协议切换功能", test_mixed_protocols)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n[{test_name}]")
        if test_func():
            passed += 1
            print(f"✓ {test_name} 测试通过")
        else:
            print(f"✗ {test_name} 测试失败")
    
    print("\n" + "=" * 50)
    print(f"测试结果: {passed}/{total} 通过")
    
    if passed == total:
        print("🎉 所有UDP和TCP修复测试通过!")
        print("\n生成的测试文件:")
        test_files = [
            "test_udp_simple.pcap",
            "test_udp_advanced.pcap",
            "test_tcp_direction_ack.pcap"
        ]
        for filename in test_files:
            if os.path.exists(filename):
                print(f"  - {filename}")
        print("\n可以用Wireshark打开这些文件查看详细内容")
        print("\n新功能特点:")
        print("- UDP支持简单模式和高级模式")
        print("- TCP方向切换时自动生成ACK")
        print("- 协议切换界面自动调整")
        return True
    else:
        print("❌ 部分测试失败，请检查错误信息。")
        return False

if __name__ == "__main__":
    success = main()
    input("\n按回车键退出...")
    sys.exit(0 if success else 1)
