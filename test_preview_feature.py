#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试数据包预览功能
验证预览列表和详细信息显示
"""

import os
import sys
import tkinter as tk

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_packet_analysis():
    """测试数据包分析功能"""
    print("测试数据包分析功能...")
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        from scapy.all import Ether, IP, TCP, UDP
        
        # 创建GUI实例
        app = PcapGeneratorGUI()
        
        # 创建测试数据包
        generator = PacketGenerator()
        
        # TCP SYN包
        tcp_syn = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                  IP(src="192.168.1.100", dst="192.168.1.200") / \
                  TCP(sport=12345, dport=80, flags="S", seq=1000)
        
        # TCP SYN-ACK包
        tcp_syn_ack = Ether(src="AA:BB:CC:DD:EE:FF", dst="00:11:22:33:44:55") / \
                      IP(src="192.168.1.200", dst="192.168.1.100") / \
                      TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
        
        # UDP包
        udp_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                     IP(src="192.168.1.100", dst="8.8.8.8") / \
                     UDP(sport=12345, dport=53) / b"DNS Query"
        
        # 测试分析功能
        tcp_syn_info = app.analyze_packet(tcp_syn)
        tcp_syn_ack_info = app.analyze_packet(tcp_syn_ack)
        udp_info = app.analyze_packet(udp_packet)
        
        # 验证TCP SYN分析
        assert tcp_syn_info['protocol'] == 'TCP', f"TCP SYN协议识别错误: {tcp_syn_info['protocol']}"
        assert 'SYN' in tcp_syn_info['summary'], f"TCP SYN标志位识别错误: {tcp_syn_info['summary']}"
        print("✓ TCP SYN包分析正确")
        
        # 验证TCP SYN-ACK分析
        assert tcp_syn_ack_info['protocol'] == 'TCP', f"TCP SYN-ACK协议识别错误: {tcp_syn_ack_info['protocol']}"
        assert 'SYN' in tcp_syn_ack_info['summary'] and 'ACK' in tcp_syn_ack_info['summary'], \
               f"TCP SYN-ACK标志位识别错误: {tcp_syn_ack_info['summary']}"
        print("✓ TCP SYN-ACK包分析正确")
        
        # 验证UDP分析
        assert udp_info['protocol'] == 'UDP', f"UDP协议识别错误: {udp_info['protocol']}"
        assert 'Len=' in udp_info['summary'], f"UDP长度信息错误: {udp_info['summary']}"
        print("✓ UDP包分析正确")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 数据包分析测试失败: {e}")
        return False

def test_preview_update():
    """测试预览列表更新功能"""
    print("\n测试预览列表更新功能...")
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        # 创建GUI实例
        app = PcapGeneratorGUI()
        
        # 设置为TCP简单模式
        app.protocol_var.set("TCP")
        app.data_mode_var.set("简单模式")
        
        # 设置数据
        app.c2s_data_var.set("Hello Server")
        app.s2c_data_var.set("Hello Client")
        app.data_size_var.set("1460")
        
        # 创建基础网络层
        generator = PacketGenerator()
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 生成数据包
        packets = app.generate_simple_tcp_packets(eth_frame, ip_layer, 12345, 80)
        app.packet_generator.packets = packets
        
        # 更新预览
        app.update_packet_preview()
        
        # 验证预览列表
        tree_children = app.packet_tree.get_children()
        assert len(tree_children) == len(packets), f"预览列表项目数量不匹配: {len(tree_children)} != {len(packets)}"
        print(f"✓ 预览列表显示 {len(tree_children)} 个数据包")
        
        # 验证第一个项目的内容
        first_item = app.packet_tree.item(tree_children[0])
        values = first_item['values']
        assert values[0] == 1, f"第一个包序号错误: {values[0]}"
        assert values[1] == 'TCP', f"第一个包协议错误: {values[1]}"
        print("✓ 预览列表内容正确")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 预览列表更新测试失败: {e}")
        return False

def test_udp_preview():
    """测试UDP数据包预览"""
    print("\n测试UDP数据包预览...")
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        app = PcapGeneratorGUI()
        
        # 设置为UDP简单模式
        app.protocol_var.set("UDP")
        app.udp_data_mode_var.set("简单模式")
        
        # 设置UDP数据
        app.udp_c2s_data_var.set("DNS Query: example.com")
        app.udp_s2c_data_var.set("DNS Response: 93.184.216.34")
        
        # 创建基础网络层
        generator = PacketGenerator()
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "8.8.8.8")
        
        # 生成UDP包
        packets = app.generate_simple_udp_packets(eth_frame, ip_layer, 12345, 53)
        app.packet_generator.packets = packets
        
        # 更新预览
        app.update_packet_preview()
        
        # 验证UDP预览
        tree_children = app.packet_tree.get_children()
        assert len(tree_children) == 2, f"UDP预览应该有2个包，实际有{len(tree_children)}个"
        
        # 检查协议类型
        for child in tree_children:
            item = app.packet_tree.item(child)
            assert item['values'][1] == 'UDP', f"协议类型应该是UDP，实际是{item['values'][1]}"
        
        print("✓ UDP数据包预览正确")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ UDP预览测试失败: {e}")
        return False

def test_mixed_protocol_preview():
    """测试混合协议预览"""
    print("\n测试混合协议预览...")
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        from scapy.all import Ether, IP, TCP, UDP
        
        app = PcapGeneratorGUI()
        
        # 手动创建混合协议包
        packets = []
        
        # TCP包
        tcp_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                     IP(src="192.168.1.100", dst="192.168.1.200") / \
                     TCP(sport=12345, dport=80, flags="S")
        packets.append(tcp_packet)
        
        # UDP包
        udp_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                     IP(src="192.168.1.100", dst="8.8.8.8") / \
                     UDP(sport=12345, dport=53)
        packets.append(udp_packet)
        
        # 设置到生成器
        app.packet_generator.packets = packets
        
        # 更新预览
        app.update_packet_preview()
        
        # 验证混合协议预览
        tree_children = app.packet_tree.get_children()
        assert len(tree_children) == 2, f"混合协议预览应该有2个包"
        
        # 检查第一个是TCP
        first_item = app.packet_tree.item(tree_children[0])
        assert first_item['values'][1] == 'TCP', f"第一个包应该是TCP"
        
        # 检查第二个是UDP
        second_item = app.packet_tree.item(tree_children[1])
        assert second_item['values'][1] == 'UDP', f"第二个包应该是UDP"
        
        print("✓ 混合协议预览正确")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 混合协议预览测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("PCAP生成工具 - 数据包预览功能测试")
    print("=" * 50)
    
    tests = [
        ("数据包分析功能", test_packet_analysis),
        ("预览列表更新", test_preview_update),
        ("UDP数据包预览", test_udp_preview),
        ("混合协议预览", test_mixed_protocol_preview)
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
        print("🎉 所有数据包预览功能测试通过!")
        print("\n预览功能特点:")
        print("- 实时显示生成的数据包列表")
        print("- 显示协议、地址、长度、摘要信息")
        print("- 支持TCP和UDP协议分析")
        print("- 双击查看数据包详细信息")
        print("- 自动更新预览列表")
        return True
    else:
        print("❌ 部分测试失败，请检查错误信息。")
        return False

if __name__ == "__main__":
    success = main()
    input("\n按回车键退出...")
    sys.exit(0 if success else 1)
