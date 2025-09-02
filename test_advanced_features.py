#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试高级数据帧配置功能
"""

import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_data_parsing():
    """测试数据解析功能"""
    print("测试数据解析功能...")
    
    try:
        from gui.main_window import PcapGeneratorGUI
        
        app = PcapGeneratorGUI()
        
        # 测试UTF-8解析
        utf8_data = app.parse_data_content("Hello World", "UTF-8")
        expected = b"Hello World"
        assert utf8_data == expected, f"UTF-8解析失败: {utf8_data} != {expected}"
        print("✓ UTF-8数据解析正常")
        
        # 测试十六进制解析
        hex_data = app.parse_data_content("48656C6C6F", "十六进制")
        expected = b"Hello"
        assert hex_data == expected, f"十六进制解析失败: {hex_data} != {expected}"
        print("✓ 十六进制数据解析正常")
        
        # 测试带分隔符的十六进制
        hex_data_sep = app.parse_data_content("48:65:6C:6C:6F", "十六进制")
        assert hex_data_sep == expected, f"带分隔符十六进制解析失败"
        print("✓ 带分隔符十六进制解析正常")
        
        # 测试中文UTF-8
        chinese_data = app.parse_data_content("你好世界", "UTF-8")
        expected_chinese = "你好世界".encode('utf-8')
        assert chinese_data == expected_chinese, f"中文UTF-8解析失败"
        print("✓ 中文UTF-8解析正常")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 数据解析测试失败: {e}")
        return False

def test_advanced_tcp_generation():
    """测试高级TCP包生成"""
    print("\n测试高级TCP包生成...")
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        import tkinter as tk
        
        # 创建GUI实例
        app = PcapGeneratorGUI()
        
        # 模拟添加数据帧
        app.add_data_frame()
        app.add_data_frame()
        
        # 设置第一个帧
        app.data_frames[0]['direction'].set("客户端→服务器")
        app.data_frames[0]['data'].set("GET / HTTP/1.1")
        app.data_frames[0]['format'].set("UTF-8")
        
        # 设置第二个帧
        app.data_frames[1]['direction'].set("服务器→客户端")
        app.data_frames[1]['data'].set("HTTP/1.1 200 OK")
        app.data_frames[1]['format'].set("UTF-8")
        
        # 创建基础网络层
        generator = PacketGenerator()
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 生成高级TCP包
        packets = app.generate_advanced_tcp_packets(eth_frame, ip_layer, 12345, 80, 1460)
        
        # 验证包数量（至少应该有握手包 + 数据包 + ACK包）
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
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 高级TCP包生成测试失败: {e}")
        return False

def test_advanced_udp_generation():
    """测试高级UDP包生成"""
    print("\n测试高级UDP包生成...")
    
    try:
        from core.packet_generator import PacketGenerator
        from gui.main_window import PcapGeneratorGUI
        
        # 创建GUI实例
        app = PcapGeneratorGUI()
        
        # 模拟添加数据帧
        app.add_data_frame()
        app.data_frames[0]['direction'].set("客户端→服务器")
        app.data_frames[0]['data'].set("DNS Query")
        app.data_frames[0]['format'].set("UTF-8")
        
        # 创建基础网络层
        generator = PacketGenerator()
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        
        # 生成高级UDP包
        packets = app.generate_advanced_udp_packets(eth_frame, ip_layer, 12345, 53)
        
        assert len(packets) >= 1, f"应该至少生成1个UDP包"
        print(f"✓ 生成了 {len(packets)} 个UDP包")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 高级UDP包生成测试失败: {e}")
        return False

def test_hex_data_validation():
    """测试十六进制数据验证"""
    print("\n测试十六进制数据验证...")
    
    try:
        from gui.main_window import PcapGeneratorGUI
        
        app = PcapGeneratorGUI()
        
        # 测试有效的十六进制
        valid_hex = ["48656C6C6F", "48:65:6C:6C:6F", "48-65-6C-6C-6F", "48 65 6C 6C 6F"]
        for hex_str in valid_hex:
            try:
                result = app.parse_data_content(hex_str, "十六进制")
                print(f"✓ 有效十六进制 '{hex_str}' 解析成功")
            except Exception as e:
                print(f"✗ 有效十六进制 '{hex_str}' 解析失败: {e}")
                return False
        
        # 测试无效的十六进制
        invalid_hex = ["48656C6C6G", "48656C6C6", "ZZZZ"]
        for hex_str in invalid_hex:
            try:
                result = app.parse_data_content(hex_str, "十六进制")
                print(f"✗ 无效十六进制 '{hex_str}' 应该解析失败但成功了")
                return False
            except ValueError:
                print(f"✓ 无效十六进制 '{hex_str}' 正确拒绝")
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 十六进制验证测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("PCAP生成工具 - 高级功能测试")
    print("=" * 40)
    
    tests = [
        ("数据解析", test_data_parsing),
        ("高级TCP生成", test_advanced_tcp_generation),
        ("高级UDP生成", test_advanced_udp_generation),
        ("十六进制验证", test_hex_data_validation)
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
    
    print("\n" + "=" * 40)
    print(f"测试结果: {passed}/{total} 通过")
    
    if passed == total:
        print("🎉 所有高级功能测试通过!")
        return True
    else:
        print("❌ 部分测试失败，请检查错误信息。")
        return False

if __name__ == "__main__":
    success = main()
    input("\n按回车键退出...")
    sys.exit(0 if success else 1)
