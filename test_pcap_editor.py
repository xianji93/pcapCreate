#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试PCAP读取和编辑功能
验证文件读取、分层显示和编辑功能
"""

import os
import sys
import tempfile

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def create_test_pcap():
    """创建测试用的PCAP文件"""
    try:
        from scapy.all import Ether, IP, TCP, UDP, wrpcap
        
        # 创建测试数据包
        packets = []
        
        # TCP包
        tcp_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                     IP(src="192.168.1.100", dst="192.168.1.200") / \
                     TCP(sport=12345, dport=80, flags="PA", seq=1000, ack=2000) / \
                     b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        packets.append(tcp_packet)
        
        # UDP包
        udp_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                     IP(src="192.168.1.100", dst="8.8.8.8") / \
                     UDP(sport=12345, dport=53) / \
                     b"DNS Query Data"
        packets.append(udp_packet)
        
        # 保存到临时文件
        test_file = "test_packets.pcap"
        wrpcap(test_file, packets)
        
        return test_file, len(packets)
        
    except Exception as e:
        print(f"创建测试PCAP文件失败: {e}")
        return None, 0

def test_pcap_loading():
    """测试PCAP文件读取功能"""
    print("测试PCAP文件读取功能...")
    
    try:
        # 创建测试文件
        test_file, packet_count = create_test_pcap()
        if not test_file:
            return False
        
        from gui.main_window import PcapGeneratorGUI
        
        # 创建GUI实例
        app = PcapGeneratorGUI()
        
        # 模拟读取PCAP文件
        from scapy.all import rdpcap
        packets = rdpcap(test_file)
        app.packet_generator.packets = packets
        
        # 验证读取结果
        assert len(app.packet_generator.packets) == packet_count, f"读取的包数量不匹配: {len(app.packet_generator.packets)} != {packet_count}"
        print(f"✓ 成功读取 {len(packets)} 个数据包")
        
        # 更新预览
        app.update_packet_preview()
        
        # 验证预览列表
        tree_children = app.packet_tree.get_children()
        assert len(tree_children) == packet_count, f"预览列表项目数量不匹配"
        print("✓ 预览列表更新正确")
        
        # 清理
        app.root.destroy()
        os.remove(test_file)
        
        return True
        
    except Exception as e:
        print(f"✗ PCAP读取测试失败: {e}")
        return False

def test_packet_analysis():
    """测试数据包分析功能"""
    print("\n测试数据包分析功能...")
    
    try:
        from gui.main_window import PcapGeneratorGUI
        from scapy.all import Ether, IP, TCP, UDP
        
        app = PcapGeneratorGUI()
        
        # 创建测试包
        tcp_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                     IP(src="192.168.1.100", dst="192.168.1.200") / \
                     TCP(sport=12345, dport=80, flags="PA", seq=1000, ack=2000) / \
                     b"Hello World"
        
        # 测试分析功能
        info = app.analyze_packet(tcp_packet)
        
        assert info['protocol'] == 'TCP', f"协议识别错误: {info['protocol']}"
        assert '192.168.1.100:12345' in info['src_addr'], f"源地址解析错误: {info['src_addr']}"
        assert '192.168.1.200:80' in info['dst_addr'], f"目标地址解析错误: {info['dst_addr']}"
        assert 'PSH' in info['summary'] and 'ACK' in info['summary'], f"TCP标志位识别错误: {info['summary']}"
        
        print("✓ TCP包分析正确")
        
        # 测试应用层数据提取
        payload = app.get_payload_data(tcp_packet)
        assert payload == b"Hello World", f"应用层数据提取错误: {payload}"
        print("✓ 应用层数据提取正确")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 数据包分析测试失败: {e}")
        return False

def test_layer_editing():
    """测试分层编辑功能"""
    print("\n测试分层编辑功能...")
    
    try:
        from gui.main_window import PcapGeneratorGUI
        from scapy.all import Ether, IP, TCP
        
        app = PcapGeneratorGUI()
        
        # 创建测试包
        test_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                      IP(src="192.168.1.100", dst="192.168.1.200", ttl=64) / \
                      TCP(sport=12345, dport=80, flags="S", seq=1000)
        
        app.packet_generator.packets = [test_packet]
        
        # 模拟创建编辑字段
        app.edit_fields = {}
        app.tcp_flags = {}
        
        # 测试以太网层编辑器创建
        import tkinter as tk
        from tkinter import ttk
        
        root = tk.Tk()
        frame = ttk.Frame(root)
        frame.pack()
        
        app.create_ethernet_editor(frame, test_packet[Ether], 0)
        
        # 验证编辑字段是否创建
        assert 'eth_0_src' in app.edit_fields, "以太网源MAC编辑字段未创建"
        assert 'eth_0_dst' in app.edit_fields, "以太网目标MAC编辑字段未创建"
        assert app.edit_fields['eth_0_src'].get() == "00:11:22:33:44:55", "以太网源MAC值不正确"
        
        print("✓ 以太网层编辑器创建正确")
        
        # 测试IP层编辑器创建
        app.create_ipv4_editor(frame, test_packet[IP], 1)
        
        assert 'ip_1_src' in app.edit_fields, "IP源地址编辑字段未创建"
        assert 'ip_1_dst' in app.edit_fields, "IP目标地址编辑字段未创建"
        assert 'ip_1_ttl' in app.edit_fields, "IP TTL编辑字段未创建"
        assert app.edit_fields['ip_1_ttl'].get() == "64", "IP TTL值不正确"
        
        print("✓ IP层编辑器创建正确")
        
        # 测试TCP层编辑器创建
        app.create_tcp_editor(frame, test_packet[TCP], 2)
        
        assert 'tcp_2_sport' in app.edit_fields, "TCP源端口编辑字段未创建"
        assert 'tcp_2_dport' in app.edit_fields, "TCP目标端口编辑字段未创建"
        assert 'tcp_2_seq' in app.edit_fields, "TCP序列号编辑字段未创建"
        assert app.edit_fields['tcp_2_seq'].get() == "1000", "TCP序列号值不正确"
        
        print("✓ TCP层编辑器创建正确")
        
        root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 分层编辑测试失败: {e}")
        return False

def test_payload_editing():
    """测试应用层数据编辑功能"""
    print("\n测试应用层数据编辑功能...")
    
    try:
        from gui.main_window import PcapGeneratorGUI
        import tkinter as tk
        from tkinter import ttk
        
        app = PcapGeneratorGUI()
        
        # 测试数据
        test_data = b"Hello World\x00\x01\x02"
        
        root = tk.Tk()
        frame = ttk.Frame(root)
        frame.pack()
        
        app.edit_fields = {}
        
        # 创建应用层编辑器
        app.create_payload_editor(frame, test_data, 3)
        
        # 验证编辑字段创建
        assert 'payload_3_format' in app.edit_fields, "应用层格式选择字段未创建"
        assert 'payload_3_text' in app.edit_fields, "应用层文本编辑字段未创建"
        
        print("✓ 应用层编辑器创建正确")
        
        # 测试十六进制显示
        text_widget = app.edit_fields['payload_3_text']
        app.update_payload_display(text_widget, test_data, "十六进制")
        
        hex_content = text_widget.get(1.0, tk.END).strip()
        expected_hex = "48 65 6c 6c 6f 20 57 6f 72 6c 64 00 01 02"
        assert expected_hex in hex_content.replace('\n', ' '), f"十六进制显示不正确: {hex_content}"
        
        print("✓ 十六进制显示正确")
        
        # 测试UTF-8显示
        utf8_data = "你好世界".encode('utf-8')
        app.update_payload_display(text_widget, utf8_data, "UTF-8")
        
        utf8_content = text_widget.get(1.0, tk.END).strip()
        assert "你好世界" in utf8_content, f"UTF-8显示不正确: {utf8_content}"
        
        print("✓ UTF-8显示正确")
        
        root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 应用层数据编辑测试失败: {e}")
        return False

def test_packet_reconstruction():
    """测试数据包重构功能"""
    print("\n测试数据包重构功能...")
    
    try:
        from gui.main_window import PcapGeneratorGUI
        from scapy.all import Ether, IP, TCP
        import tkinter as tk
        
        app = PcapGeneratorGUI()
        
        # 创建原始测试包
        original_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                         IP(src="192.168.1.100", dst="192.168.1.200", ttl=64) / \
                         TCP(sport=12345, dport=80, flags="S", seq=1000)
        
        app.packet_generator.packets = [original_packet]
        app.current_packet_index = tk.IntVar(value=0)
        
        # 模拟编辑字段
        app.edit_fields = {
            'eth_0_src': tk.StringVar(value="00:AA:BB:CC:DD:EE"),  # 修改源MAC
            'eth_0_dst': tk.StringVar(value="FF:EE:DD:CC:BB:AA"),  # 修改目标MAC
            'eth_0_type': tk.StringVar(value="0x0800"),
            'ip_1_src': tk.StringVar(value="10.0.0.1"),           # 修改源IP
            'ip_1_dst': tk.StringVar(value="10.0.0.2"),           # 修改目标IP
            'ip_1_ttl': tk.StringVar(value="128"),                # 修改TTL
            'ip_1_version': tk.StringVar(value="4"),
            'ip_1_ihl': tk.StringVar(value="5"),
            'ip_1_tos': tk.StringVar(value="0"),
            'ip_1_len': tk.StringVar(value="40"),
            'ip_1_id': tk.StringVar(value="1"),
            'ip_1_flags': tk.StringVar(value="2"),
            'ip_1_proto': tk.StringVar(value="6"),
            'tcp_2_sport': tk.StringVar(value="54321"),           # 修改源端口
            'tcp_2_dport': tk.StringVar(value="443"),             # 修改目标端口
            'tcp_2_seq': tk.StringVar(value="2000"),              # 修改序列号
            'tcp_2_ack': tk.StringVar(value="0"),
            'tcp_2_window': tk.StringVar(value="8192"),
            'tcp_2_urgptr': tk.StringVar(value="0")
        }
        
        app.tcp_flags = {
            'tcp_2_syn': tk.BooleanVar(value=True),
            'tcp_2_ack': tk.BooleanVar(value=False),
            'tcp_2_psh': tk.BooleanVar(value=False),
            'tcp_2_fin': tk.BooleanVar(value=False),
            'tcp_2_rst': tk.BooleanVar(value=False),
            'tcp_2_urg': tk.BooleanVar(value=False)
        }
        
        # 重构数据包
        new_packet = app.rebuild_packet(0)
        
        assert new_packet is not None, "数据包重构失败"
        
        # 验证修改是否生效
        assert new_packet[Ether].src == "00:AA:BB:CC:DD:EE", f"源MAC修改失败: {new_packet[Ether].src}"
        assert new_packet[IP].src == "10.0.0.1", f"源IP修改失败: {new_packet[IP].src}"
        assert new_packet[IP].ttl == 128, f"TTL修改失败: {new_packet[IP].ttl}"
        assert new_packet[TCP].sport == 54321, f"源端口修改失败: {new_packet[TCP].sport}"
        assert new_packet[TCP].dport == 443, f"目标端口修改失败: {new_packet[TCP].dport}"
        assert new_packet[TCP].seq == 2000, f"序列号修改失败: {new_packet[TCP].seq}"
        
        print("✓ 数据包重构成功，修改已生效")
        
        return True
        
    except Exception as e:
        print(f"✗ 数据包重构测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("PCAP生成工具 - PCAP读取和编辑功能测试")
    print("=" * 60)
    
    tests = [
        ("PCAP文件读取", test_pcap_loading),
        ("数据包分析", test_packet_analysis),
        ("分层编辑", test_layer_editing),
        ("应用层数据编辑", test_payload_editing),
        ("数据包重构", test_packet_reconstruction)
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
    
    print("\n" + "=" * 60)
    print(f"测试结果: {passed}/{total} 通过")
    
    if passed == total:
        print("🎉 所有PCAP编辑功能测试通过!")
        print("\n编辑功能特点:")
        print("- 读取标准PCAP/PCAPNG文件")
        print("- 分层显示和编辑（以太网、IP、TCP/UDP、应用层）")
        print("- 实时预览修改效果")
        print("- 支持多种数据格式（十六进制、ASCII、UTF-8）")
        print("- 完整的数据包重构功能")
        return True
    else:
        print("❌ 部分测试失败，请检查错误信息。")
        return False

if __name__ == "__main__":
    success = main()
    input("\n按回车键退出...")
    sys.exit(0 if success else 1)
