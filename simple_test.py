#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单测试脚本 - 验证PCAP生成工具的核心功能
"""

import os
import sys

def test_imports():
    """测试导入"""
    print("测试模块导入...")
    try:
        from scapy.all import Ether, IP, TCP, UDP, wrpcap
        print("✓ scapy导入成功")
        
        from utils.validators import validate_mac_address, validate_ipv4_address
        print("✓ validators模块导入成功")
        
        from core.packet_generator import PacketGenerator
        print("✓ PacketGenerator导入成功")
        
        return True
    except ImportError as e:
        print(f"✗ 导入失败: {e}")
        return False

def test_basic_functionality():
    """测试基本功能"""
    print("\n测试基本功能...")
    
    try:
        from core.packet_generator import PacketGenerator
        from utils.validators import validate_mac_address, normalize_mac_address
        
        # 测试MAC地址验证
        assert validate_mac_address("00:11:22:33:44:55"), "MAC地址验证失败"
        print("✓ MAC地址验证正常")
        
        # 测试数据包生成器
        generator = PacketGenerator()
        
        # 创建以太网帧
        eth_frame = generator.create_ethernet_frame("00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF")
        print("✓ 以太网帧创建成功")
        
        # 创建IP层
        ip_layer = generator.create_ip_layer(4, "192.168.1.100", "192.168.1.200")
        print("✓ IP层创建成功")
        
        # 生成TCP连接
        packets = generator.generate_tcp_connection(eth_frame, ip_layer, 12345, 80, 0)
        assert len(packets) == 3, f"TCP连接应该生成3个包，实际生成了{len(packets)}个"
        print(f"✓ TCP连接生成成功 ({len(packets)}个包)")
        
        # 测试PCAP保存
        generator.packets = packets
        test_file = "test_output.pcap"
        
        try:
            count = generator.save_to_pcap(test_file)
            assert count == len(packets), "保存的包数量不匹配"
            assert os.path.exists(test_file), "PCAP文件未创建"
            print(f"✓ PCAP文件保存成功 ({count}个包)")
            
            # 清理测试文件
            os.remove(test_file)
            print("✓ 测试文件清理完成")
            
        except Exception as e:
            print(f"✗ PCAP保存测试失败: {e}")
            return False
            
        return True
        
    except Exception as e:
        print(f"✗ 基本功能测试失败: {e}")
        return False

def test_gui_creation():
    """测试GUI创建（不显示窗口）"""
    print("\n测试GUI创建...")
    
    try:
        import tkinter as tk
        from gui.main_window import PcapGeneratorGUI
        
        # 创建GUI实例但不运行
        app = PcapGeneratorGUI()
        print("✓ GUI创建成功")
        
        # 测试一些基本属性
        assert hasattr(app, 'packet_generator'), "GUI缺少packet_generator属性"
        assert hasattr(app, 'root'), "GUI缺少root属性"
        print("✓ GUI属性检查通过")
        
        # 销毁窗口
        app.root.destroy()
        print("✓ GUI清理完成")
        
        return True
        
    except Exception as e:
        print(f"✗ GUI测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("PCAP生成工具 - 简单功能测试")
    print("=" * 40)
    
    tests = [
        ("模块导入", test_imports),
        ("基本功能", test_basic_functionality),
        ("GUI创建", test_gui_creation)
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
        print("🎉 所有测试通过! 工具可以正常使用。")
        return True
    else:
        print("❌ 部分测试失败，请检查错误信息。")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
