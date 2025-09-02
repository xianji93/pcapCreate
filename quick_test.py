#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速验证脚本 - 测试核心功能是否可用
"""

def test_scapy_import():
    """测试scapy导入"""
    try:
        from scapy.all import Ether, IP, TCP, UDP, wrpcap
        print("✓ scapy导入成功")
        return True
    except ImportError as e:
        print(f"✗ scapy导入失败: {e}")
        print("请运行: pip install scapy")
        return False

def test_basic_packet_creation():
    """测试基本数据包创建"""
    try:
        from scapy.all import Ether, IP, TCP
        
        # 创建简单的TCP包
        packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                 IP(src="192.168.1.100", dst="192.168.1.200") / \
                 TCP(sport=12345, dport=80, flags="S")
        
        print("✓ 基本数据包创建成功")
        print(f"  包大小: {len(packet)} 字节")
        return True
    except Exception as e:
        print(f"✗ 数据包创建失败: {e}")
        return False

def test_pcap_save():
    """测试PCAP文件保存"""
    try:
        from scapy.all import Ether, IP, TCP, wrpcap
        import os
        
        # 创建测试包
        packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                 IP(src="192.168.1.100", dst="192.168.1.200") / \
                 TCP(sport=12345, dport=80, flags="S")
        
        # 保存到文件
        test_file = "test.pcap"
        wrpcap(test_file, [packet])
        
        if os.path.exists(test_file):
            file_size = os.path.getsize(test_file)
            print(f"✓ PCAP文件保存成功 ({file_size} 字节)")
            os.remove(test_file)  # 清理测试文件
            return True
        else:
            print("✗ PCAP文件未创建")
            return False
            
    except Exception as e:
        print(f"✗ PCAP保存失败: {e}")
        return False

def test_gui_modules():
    """测试GUI模块导入"""
    try:
        import tkinter as tk
        print("✓ tkinter导入成功")
        
        from gui.main_window import PcapGeneratorGUI
        print("✓ GUI模块导入成功")
        return True
    except ImportError as e:
        print(f"✗ GUI模块导入失败: {e}")
        return False

def main():
    """主测试函数"""
    print("PCAP生成工具 - 快速验证")
    print("=" * 30)
    
    tests = [
        ("Scapy库", test_scapy_import),
        ("数据包创建", test_basic_packet_creation),
        ("PCAP保存", test_pcap_save),
        ("GUI模块", test_gui_modules)
    ]
    
    passed = 0
    for name, test_func in tests:
        print(f"\n[{name}]")
        if test_func():
            passed += 1
    
    print(f"\n结果: {passed}/{len(tests)} 通过")
    
    if passed == len(tests):
        print("\n🎉 所有测试通过! 可以运行: python main.py")
    else:
        print("\n❌ 部分测试失败，请检查依赖安装")
    
    input("\n按回车键退出...")

if __name__ == "__main__":
    main()
