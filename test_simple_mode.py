#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试简单模式的新功能
验证C2S和S2C数据框功能
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_simple_mode_c2s_s2c():
    """测试简单模式的C2S和S2C数据框"""
    print("测试简单模式C2S和S2C数据框...")
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        # 创建GUI实例
        app = PcapGeneratorGUI()
        
        # 设置为简单模式
        app.data_mode_var.set("简单模式")
        
        # 设置C2S数据
        app.c2s_data_var.set("GET /api/data HTTP/1.1\\r\\nHost: api.example.com\\r\\n\\r\\n")
        
        # 设置S2C数据
        app.s2c_data_var.set("HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n{\"status\":\"success\"}")
        
        # 设置数据大小
        app.data_size_var.set("1460")
        
        # 创建基础网络层
        generator = PacketGenerator()
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 生成简单模式TCP包
        packets = app.generate_simple_tcp_packets(eth_frame, ip_layer, 12345, 80)
        
        # 验证包数量（握手3个 + C2S数据和ACK + S2C数据和ACK）
        assert len(packets) >= 7, f"生成的包数量不足: {len(packets)}"
        print(f"✓ 生成了 {len(packets)} 个TCP包")
        
        # 验证前三个包是握手包
        from scapy.layers.inet import TCP
        tcp1 = packets[0][TCP]
        tcp2 = packets[1][TCP]
        tcp3 = packets[2][TCP]
        
        assert tcp1.flags == 2, "第一个包应该是SYN"  # SYN
        assert tcp2.flags == 18, "第二个包应该是SYN-ACK"  # SYN+ACK
        assert tcp3.flags == 16, "第三个包应该是ACK"  # ACK
        print("✓ TCP三次握手包正确")
        
        # 验证数据包内容
        data_packets = [p for p in packets[3:] if TCP in p and len(p[TCP].payload) > 0]
        assert len(data_packets) >= 2, "应该至少有2个数据包（C2S和S2C）"
        print("✓ 包含C2S和S2C数据包")
        
        # 保存测试文件
        generator.packets = packets
        filename = "test_simple_mode.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 简单模式测试失败: {e}")
        return False

def test_escape_sequences():
    """测试转义序列解析"""
    print("\n测试转义序列解析...")
    
    try:
        from gui.main_window import PcapGeneratorGUI
        
        app = PcapGeneratorGUI()
        
        # 测试转义序列
        test_cases = [
            ("Hello\\r\\nWorld", "Hello\r\nWorld"),
            ("Tab\\tSeparated", "Tab\tSeparated"),
            ("Line1\\r\\nLine2\\r\\n", "Line1\r\nLine2\r\n"),
            ("No escape", "No escape")
        ]
        
        for input_str, expected in test_cases:
            result = app.parse_escape_sequences(input_str)
            assert result == expected, f"转义序列解析失败: '{input_str}' -> '{result}' != '{expected}'"
            print(f"✓ '{input_str}' -> '{expected}'")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 转义序列测试失败: {e}")
        return False

def test_large_data_fragmentation():
    """测试大数据分片"""
    print("\n测试大数据分片...")
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        app = PcapGeneratorGUI()
        
        # 设置较小的数据大小来测试分片
        app.data_size_var.set("100")  # 100字节分片
        
        # 设置大数据
        large_c2s = "A" * 250  # 250字节，应该分成3片
        large_s2c = "B" * 180  # 180字节，应该分成2片
        
        app.c2s_data_var.set(large_c2s)
        app.s2c_data_var.set(large_s2c)
        
        # 创建基础网络层
        generator = PacketGenerator()
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 生成包
        packets = app.generate_simple_tcp_packets(eth_frame, ip_layer, 12345, 80)
        
        print(f"✓ 生成了 {len(packets)} 个包")
        print(f"  原始C2S数据: {len(large_c2s)} 字节")
        print(f"  原始S2C数据: {len(large_s2c)} 字节")
        print(f"  分片大小: 100 字节")
        
        # 验证分片数量
        from scapy.layers.inet import TCP
        data_packets = [p for p in packets[3:] if TCP in p and len(p[TCP].payload) > 0]
        expected_fragments = 3 + 2  # C2S 3片 + S2C 2片
        assert len(data_packets) == expected_fragments, f"分片数量不正确: {len(data_packets)} != {expected_fragments}"
        print("✓ 数据分片正确")
        
        # 保存测试文件
        generator.packets = packets
        filename = "test_fragmentation.pcap"
        generator.save_to_pcap(filename)
        print(f"✓ 已保存到 {filename}")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 分片测试失败: {e}")
        return False

def test_empty_data_handling():
    """测试空数据处理"""
    print("\n测试空数据处理...")
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        app = PcapGeneratorGUI()
        
        # 只设置C2S数据，S2C为空
        app.c2s_data_var.set("Only C2S data")
        app.s2c_data_var.set("")
        app.data_size_var.set("1460")
        
        # 创建基础网络层
        generator = PacketGenerator()
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 生成包
        packets = app.generate_simple_tcp_packets(eth_frame, ip_layer, 12345, 80)
        
        # 应该有握手包 + C2S数据包 + ACK，但没有S2C数据包
        print(f"✓ 只有C2S数据时生成了 {len(packets)} 个包")
        
        # 测试只有S2C数据
        app.c2s_data_var.set("")
        app.s2c_data_var.set("Only S2C data")
        
        packets2 = app.generate_simple_tcp_packets(eth_frame, ip_layer, 12345, 80)
        print(f"✓ 只有S2C数据时生成了 {len(packets2)} 个包")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 空数据测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("PCAP生成工具 - 简单模式新功能测试")
    print("=" * 50)
    
    tests = [
        ("C2S和S2C数据框", test_simple_mode_c2s_s2c),
        ("转义序列解析", test_escape_sequences),
        ("大数据分片", test_large_data_fragmentation),
        ("空数据处理", test_empty_data_handling)
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
        print("🎉 所有简单模式新功能测试通过!")
        print("\n生成的测试文件:")
        for filename in ["test_simple_mode.pcap", "test_fragmentation.pcap"]:
            if os.path.exists(filename):
                print(f"  - {filename}")
        print("\n可以用Wireshark打开这些文件查看详细内容")
        return True
    else:
        print("❌ 部分测试失败，请检查错误信息。")
        return False

if __name__ == "__main__":
    success = main()
    input("\n按回车键退出...")
    sys.exit(0 if success else 1)
