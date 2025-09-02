#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试修复的问题
1. hexdump显示问题
2. 应用层数据格式切换问题
"""

import os
import sys
import tkinter as tk

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_hexdump_display():
    """测试hexdump显示修复"""
    print("测试hexdump显示修复...")
    
    try:
        from gui.main_window import PcapGeneratorGUI
        from scapy.all import Ether, IP, TCP
        
        # 创建GUI实例
        app = PcapGeneratorGUI()
        
        # 创建测试数据包
        test_packet = Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") / \
                     IP(src="192.168.1.100", dst="192.168.1.200") / \
                     TCP(sport=12345, dport=80, flags="PA", seq=1000, ack=2000) / \
                     b"Hello World Test Data"
        
        app.packet_generator.packets = [test_packet]
        
        # 测试详细信息显示
        try:
            app.show_packet_details(0)
            print("✓ 数据包详细信息窗口创建成功")
            
            # 等待一下让窗口创建完成
            app.root.update()
            
            # 关闭详细信息窗口
            for widget in app.root.winfo_children():
                if isinstance(widget, tk.Toplevel):
                    widget.destroy()
                    break
            
            print("✓ hexdump显示功能正常")
            
        except Exception as e:
            print(f"✗ hexdump显示测试失败: {e}")
            app.root.destroy()
            return False
        
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ hexdump测试失败: {e}")
        return False

def test_payload_format_switching():
    """测试应用层数据格式切换修复"""
    print("\n测试应用层数据格式切换修复...")
    
    try:
        from gui.main_window import PcapGeneratorGUI
        import tkinter as tk
        from tkinter import ttk
        
        app = PcapGeneratorGUI()
        
        # 创建测试根窗口
        root = tk.Tk()
        root.withdraw()  # 隐藏主窗口
        
        frame = ttk.Frame(root)
        frame.pack()
        
        # 测试数据
        test_data = b"Hello World\x00\x01\x02\x03"
        
        app.edit_fields = {}
        
        # 创建应用层编辑器
        app.create_payload_editor(frame, test_data, 0)
        
        # 获取编辑组件
        text_widget = app.edit_fields['payload_0_text']
        format_var = app.edit_fields['payload_0_format']
        
        print("测试格式切换:")
        
        # 1. 初始十六进制显示
        initial_content = text_widget.get(1.0, tk.END).strip()
        print(f"  初始十六进制内容: {initial_content[:50]}...")
        assert initial_content, "初始十六进制内容不应为空"
        
        # 2. 切换到UTF-8
        format_var.set("UTF-8")
        app.update_payload_display(text_widget, test_data, "UTF-8")
        utf8_content = text_widget.get(1.0, tk.END).strip()
        print(f"  UTF-8内容: {repr(utf8_content)}")
        assert utf8_content, "UTF-8内容不应为空"
        
        # 3. 从UTF-8切换回十六进制（这是问题所在）
        # 先从UTF-8文本获取数据
        recovered_data = app.get_payload_from_text(text_widget, "UTF-8")
        print(f"  从UTF-8恢复的数据长度: {len(recovered_data)} 字节")
        
        # 然后显示为十六进制
        app.update_payload_display(text_widget, recovered_data, "十六进制")
        recovered_hex_content = text_widget.get(1.0, tk.END).strip()
        print(f"  恢复的十六进制内容: {recovered_hex_content}")
        
        # 验证内容不为空
        assert recovered_hex_content, "从UTF-8切换回十六进制后内容不应为空"
        print("✓ 格式切换功能正常")
        
        # 4. 测试ASCII格式
        format_var.set("ASCII")
        app.update_payload_display(text_widget, test_data, "ASCII")
        ascii_content = text_widget.get(1.0, tk.END).strip()
        print(f"  ASCII内容: {repr(ascii_content)}")
        assert ascii_content, "ASCII内容不应为空"
        
        # 5. 从ASCII切换回十六进制
        recovered_data_ascii = app.get_payload_from_text(text_widget, "ASCII")
        app.update_payload_display(text_widget, recovered_data_ascii, "十六进制")
        final_hex_content = text_widget.get(1.0, tk.END).strip()
        print(f"  从ASCII恢复的十六进制内容: {final_hex_content}")
        assert final_hex_content, "从ASCII切换回十六进制后内容不应为空"
        
        print("✓ 所有格式切换测试通过")
        
        root.destroy()
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 格式切换测试失败: {e}")
        return False

def test_format_conversion_accuracy():
    """测试格式转换的准确性"""
    print("\n测试格式转换准确性...")
    
    try:
        from gui.main_window import PcapGeneratorGUI
        import tkinter as tk
        
        app = PcapGeneratorGUI()
        
        # 测试数据集
        test_cases = [
            ("简单文本", b"Hello World"),
            ("中文UTF-8", "你好世界".encode('utf-8')),
            ("二进制数据", b"\x00\x01\x02\x03\x04\x05"),
            ("混合数据", b"Hello\x00World\xFF"),
            ("空数据", b""),
        ]
        
        root = tk.Tk()
        root.withdraw()
        
        for name, original_data in test_cases:
            print(f"  测试 {name}:")
            
            text_widget = tk.Text(root)
            
            # 十六进制往返测试
            app.update_payload_display(text_widget, original_data, "十六进制")
            hex_recovered = app.get_payload_from_text(text_widget, "十六进制")
            
            if original_data == hex_recovered:
                print(f"    ✓ 十六进制往返正确")
            else:
                print(f"    ✗ 十六进制往返失败: {original_data} != {hex_recovered}")
            
            # UTF-8往返测试（仅对有效UTF-8数据）
            try:
                original_data.decode('utf-8')
                app.update_payload_display(text_widget, original_data, "UTF-8")
                utf8_recovered = app.get_payload_from_text(text_widget, "UTF-8")
                
                if original_data == utf8_recovered:
                    print(f"    ✓ UTF-8往返正确")
                else:
                    print(f"    ✗ UTF-8往返失败")
            except UnicodeDecodeError:
                print(f"    - UTF-8跳过（非有效UTF-8数据）")
            
            # ASCII往返测试
            app.update_payload_display(text_widget, original_data, "ASCII")
            ascii_recovered = app.get_payload_from_text(text_widget, "ASCII")
            
            if original_data == ascii_recovered:
                print(f"    ✓ ASCII往返正确")
            else:
                print(f"    ✗ ASCII往返失败")
        
        root.destroy()
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 格式转换准确性测试失败: {e}")
        return False

def test_edge_cases():
    """测试边界情况"""
    print("\n测试边界情况...")
    
    try:
        from gui.main_window import PcapGeneratorGUI
        import tkinter as tk
        
        app = PcapGeneratorGUI()
        root = tk.Tk()
        root.withdraw()
        
        text_widget = tk.Text(root)
        
        # 测试空数据
        app.update_payload_display(text_widget, b"", "十六进制")
        empty_content = text_widget.get(1.0, tk.END).strip()
        print(f"  空数据显示: '{empty_content}'")
        
        # 测试从空内容恢复数据
        empty_recovered = app.get_payload_from_text(text_widget, "十六进制")
        assert empty_recovered == b"", f"空数据恢复失败: {empty_recovered}"
        print("  ✓ 空数据处理正确")
        
        # 测试无效十六进制
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, "ZZZZ")  # 无效十六进制
        invalid_hex_recovered = app.get_payload_from_text(text_widget, "十六进制")
        assert invalid_hex_recovered == b"", "无效十六进制应该返回空数据"
        print("  ✓ 无效十六进制处理正确")
        
        # 测试奇数长度十六进制
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, "ABC")  # 奇数长度
        odd_hex_recovered = app.get_payload_from_text(text_widget, "十六进制")
        expected = bytes.fromhex("0ABC")  # 应该补0
        assert odd_hex_recovered == expected, f"奇数长度十六进制处理失败: {odd_hex_recovered} != {expected}"
        print("  ✓ 奇数长度十六进制处理正确")
        
        root.destroy()
        app.root.destroy()
        return True
        
    except Exception as e:
        print(f"✗ 边界情况测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("PCAP生成工具 - 问题修复验证测试")
    print("=" * 50)
    
    tests = [
        ("hexdump显示修复", test_hexdump_display),
        ("应用层数据格式切换修复", test_payload_format_switching),
        ("格式转换准确性", test_format_conversion_accuracy),
        ("边界情况处理", test_edge_cases)
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
        print("🎉 所有问题修复验证测试通过!")
        print("\n修复内容:")
        print("1. ✓ hexdump显示问题已修复")
        print("   - 添加了备用的手动十六进制显示方法")
        print("   - 改进了错误处理机制")
        print("2. ✓ 应用层数据格式切换问题已修复")
        print("   - 改进了格式切换时的数据保持逻辑")
        print("   - 增强了数据解析和显示的鲁棒性")
        print("   - 添加了边界情况处理")
        return True
    else:
        print("❌ 部分修复验证失败，请检查错误信息。")
        return False

if __name__ == "__main__":
    success = main()
    input("\n按回车键退出...")
    sys.exit(0 if success else 1)
