#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主GUI窗口
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys
import random

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.packet_generator import PacketGenerator
from utils.validators import validate_mac_address, validate_ipv4_address, validate_ipv6_address, validate_port, normalize_mac_address

# 导入scapy类型用于类型检查
try:
    from scapy.layers.inet import IP
except ImportError:
    # 如果scapy未安装，定义一个占位符
    class IP:
        pass

class PcapGeneratorGUI:
    """PCAP生成器GUI主窗口"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PCAP生成工具 v2.0 - 支持高级数据帧配置")
        self.root.geometry("800x900")
        self.root.resizable(True, True)
        
        # 设置窗口图标（如果有的话）
        try:
            self.root.iconbitmap('icon.ico')
        except:
            pass
            
        self.packet_generator = PacketGenerator()
        self.setup_ui()
        
    def setup_ui(self):
        """设置用户界面"""
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        row = 0
        
        # 标题
        title_label = ttk.Label(main_frame, text="PCAP网络包生成工具", font=("Arial", 16, "bold"))
        title_label.grid(row=row, column=0, columnspan=2, pady=(0, 20))
        row += 1
        
        # MAC地址配置
        mac_frame = ttk.LabelFrame(main_frame, text="以太网配置", padding="10")
        mac_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        mac_frame.columnconfigure(1, weight=1)
        row += 1
        
        ttk.Label(mac_frame, text="源MAC地址:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.src_mac_var = tk.StringVar(value="00:11:22:33:44:55")
        self.src_mac_entry = ttk.Entry(mac_frame, textvariable=self.src_mac_var, width=20)
        self.src_mac_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        ttk.Label(mac_frame, text="目标MAC地址:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.dst_mac_var = tk.StringVar(value="AA:BB:CC:DD:EE:FF")
        self.dst_mac_entry = ttk.Entry(mac_frame, textvariable=self.dst_mac_var, width=20)
        self.dst_mac_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        # IP配置
        ip_frame = ttk.LabelFrame(main_frame, text="IP层配置", padding="10")
        ip_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        ip_frame.columnconfigure(1, weight=1)
        row += 1
        
        # IP版本选择
        ttk.Label(ip_frame, text="IP版本:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.ip_version_var = tk.StringVar(value="IPv4")
        ip_version_combo = ttk.Combobox(ip_frame, textvariable=self.ip_version_var, 
                                       values=["IPv4", "IPv6"], state="readonly", width=10)
        ip_version_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        ip_version_combo.bind('<<ComboboxSelected>>', self.on_ip_version_change)
        
        # IP地址
        ttk.Label(ip_frame, text="源IP地址:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.src_ip_var = tk.StringVar(value="192.168.1.100")
        self.src_ip_entry = ttk.Entry(ip_frame, textvariable=self.src_ip_var, width=30)
        self.src_ip_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        ttk.Label(ip_frame, text="目标IP地址:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.dst_ip_var = tk.StringVar(value="192.168.1.200")
        self.dst_ip_entry = ttk.Entry(ip_frame, textvariable=self.dst_ip_var, width=30)
        self.dst_ip_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        
        # IP参数配置框架
        self.ip_params_frame = ttk.Frame(ip_frame)
        self.ip_params_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        self.ip_params_frame.columnconfigure(1, weight=1)
        self.ip_params_frame.columnconfigure(3, weight=1)
        
        self.setup_ipv4_params()
        
        # 传输层配置
        transport_frame = ttk.LabelFrame(main_frame, text="传输层配置", padding="10")
        transport_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        transport_frame.columnconfigure(1, weight=1)
        row += 1
        
        # 协议选择
        ttk.Label(transport_frame, text="协议:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.protocol_var = tk.StringVar(value="TCP")
        protocol_combo = ttk.Combobox(transport_frame, textvariable=self.protocol_var,
                                     values=["TCP", "UDP"], state="readonly", width=10)
        protocol_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        protocol_combo.bind('<<ComboboxSelected>>', self.on_protocol_change)
        
        # 端口配置
        ttk.Label(transport_frame, text="源端口:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.src_port_var = tk.StringVar(value="12345")
        self.src_port_entry = ttk.Entry(transport_frame, textvariable=self.src_port_var, width=10)
        self.src_port_entry.grid(row=1, column=1, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        
        ttk.Label(transport_frame, text="目标端口:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.dst_port_var = tk.StringVar(value="80")
        self.dst_port_entry = ttk.Entry(transport_frame, textvariable=self.dst_port_var, width=10)
        self.dst_port_entry.grid(row=2, column=1, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        
        # TCP特有配置
        self.tcp_frame = ttk.Frame(transport_frame)
        self.tcp_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        # 数据配置模式选择
        ttk.Label(self.tcp_frame, text="数据配置模式:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.data_mode_var = tk.StringVar(value="简单模式")
        data_mode_combo = ttk.Combobox(self.tcp_frame, textvariable=self.data_mode_var,
                                      values=["简单模式", "高级模式"], state="readonly", width=12)
        data_mode_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        data_mode_combo.bind('<<ComboboxSelected>>', self.on_data_mode_change)

        # 简单模式配置
        self.simple_data_frame = ttk.Frame(self.tcp_frame)
        self.simple_data_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        self.simple_data_frame.columnconfigure(1, weight=1)

        # 数据大小配置
        size_frame = ttk.Frame(self.simple_data_frame)
        size_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(size_frame, text="数据大小(字节):").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.data_size_var = tk.StringVar(value="1460")
        self.data_size_entry = ttk.Entry(size_frame, textvariable=self.data_size_var, width=10)
        self.data_size_entry.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))

        # C2S数据配置
        c2s_frame = ttk.LabelFrame(self.simple_data_frame, text="客户端→服务器数据 (C2S)", padding="5")
        c2s_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        c2s_frame.columnconfigure(1, weight=1)

        ttk.Label(c2s_frame, text="UTF-8内容:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.c2s_data_var = tk.StringVar(value="GET /index.html HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")
        self.c2s_data_entry = ttk.Entry(c2s_frame, textvariable=self.c2s_data_var, width=50)
        self.c2s_data_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        # S2C数据配置
        s2c_frame = ttk.LabelFrame(self.simple_data_frame, text="服务器→客户端数据 (S2C)", padding="5")
        s2c_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        s2c_frame.columnconfigure(1, weight=1)

        ttk.Label(s2c_frame, text="UTF-8内容:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.s2c_data_var = tk.StringVar(value="HTTP/1.1 200 OK\\r\\nContent-Length: 13\\r\\n\\r\\nHello World!")
        self.s2c_data_entry = ttk.Entry(s2c_frame, textvariable=self.s2c_data_var, width=50)
        self.s2c_data_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        # 高级模式配置
        self.advanced_data_frame = ttk.Frame(self.tcp_frame)
        self.advanced_data_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        self.setup_advanced_data_config()
        
        # 生成和保存按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=row, column=0, columnspan=2, pady=(20, 0))
        row += 1
        
        self.generate_btn = ttk.Button(button_frame, text="生成数据包", command=self.generate_packets)
        self.generate_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.save_btn = ttk.Button(button_frame, text="保存PCAP文件", command=self.save_pcap, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT)
        
        # 状态显示
        self.status_var = tk.StringVar(value="就绪")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, foreground="blue")
        status_label.grid(row=row, column=0, columnspan=2, pady=(10, 0))
        
    def setup_ipv4_params(self):
        """设置IPv4参数"""
        # 清除现有控件
        for widget in self.ip_params_frame.winfo_children():
            widget.destroy()
            
        ttk.Label(self.ip_params_frame, text="TTL:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.ttl_var = tk.StringVar(value="64")
        ttk.Entry(self.ip_params_frame, textvariable=self.ttl_var, width=8).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        ttk.Label(self.ip_params_frame, text="TOS:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.tos_var = tk.StringVar(value="0")
        ttk.Entry(self.ip_params_frame, textvariable=self.tos_var, width=8).grid(row=0, column=3, sticky=tk.W)
        
    def setup_ipv6_params(self):
        """设置IPv6参数"""
        # 清除现有控件
        for widget in self.ip_params_frame.winfo_children():
            widget.destroy()
            
        ttk.Label(self.ip_params_frame, text="Hop Limit:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.hlim_var = tk.StringVar(value="64")
        ttk.Entry(self.ip_params_frame, textvariable=self.hlim_var, width=8).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        ttk.Label(self.ip_params_frame, text="Traffic Class:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.tc_var = tk.StringVar(value="0")
        ttk.Entry(self.ip_params_frame, textvariable=self.tc_var, width=8).grid(row=0, column=3, sticky=tk.W)
        
    def on_ip_version_change(self, event=None):
        """IP版本改变时的处理"""
        if self.ip_version_var.get() == "IPv4":
            self.src_ip_var.set("192.168.1.100")
            self.dst_ip_var.set("192.168.1.200")
            self.setup_ipv4_params()
        else:
            self.src_ip_var.set("2001:db8::1")
            self.dst_ip_var.set("2001:db8::2")
            self.setup_ipv6_params()
            
    def on_protocol_change(self, event=None):
        """协议改变时的处理"""
        if self.protocol_var.get() == "TCP":
            self.tcp_frame.grid()
        else:
            self.tcp_frame.grid_remove()

    def on_data_mode_change(self, event=None):
        """数据配置模式改变时的处理"""
        if self.data_mode_var.get() == "简单模式":
            self.simple_data_frame.grid()
            self.advanced_data_frame.grid_remove()
        else:
            self.simple_data_frame.grid_remove()
            self.advanced_data_frame.grid()

    def setup_advanced_data_config(self):
        """设置高级数据配置界面"""
        # 最大帧大小设置
        frame_size_frame = ttk.Frame(self.advanced_data_frame)
        frame_size_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(frame_size_frame, text="最大帧大小(字节):").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.max_frame_size_var = tk.StringVar(value="1460")
        ttk.Entry(frame_size_frame, textvariable=self.max_frame_size_var, width=10).grid(row=0, column=1, sticky=tk.W)

        # 数据帧列表
        list_frame = ttk.LabelFrame(self.advanced_data_frame, text="数据帧配置", padding="5")
        list_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        list_frame.columnconfigure(0, weight=1)

        # 列表头部
        header_frame = ttk.Frame(list_frame)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        header_frame.columnconfigure(1, weight=1)

        ttk.Label(header_frame, text="方向", width=8).grid(row=0, column=0, padx=(0, 5))
        ttk.Label(header_frame, text="数据内容", width=30).grid(row=0, column=1, padx=(0, 5))
        ttk.Label(header_frame, text="格式", width=8).grid(row=0, column=2, padx=(0, 5))
        ttk.Label(header_frame, text="操作", width=8).grid(row=0, column=3)

        # 数据帧列表容器
        self.frames_container = ttk.Frame(list_frame)
        self.frames_container.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.frames_container.columnconfigure(1, weight=1)

        # 数据帧列表
        self.data_frames = []

        # 添加按钮
        add_frame = ttk.Frame(list_frame)
        add_frame.grid(row=2, column=0, sticky=tk.W, pady=(5, 0))

        ttk.Button(add_frame, text="添加帧", command=self.add_data_frame).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(add_frame, text="清空所有", command=self.clear_data_frames).pack(side=tk.LEFT)

        # 默认添加一个数据帧
        self.add_data_frame()

        # 初始隐藏高级模式
        self.advanced_data_frame.grid_remove()

    def add_data_frame(self):
        """添加一个数据帧配置行"""
        frame_index = len(self.data_frames)

        # 创建帧配置行
        frame_row = ttk.Frame(self.frames_container)
        frame_row.grid(row=frame_index, column=0, sticky=(tk.W, tk.E), pady=2)
        frame_row.columnconfigure(1, weight=1)

        # 方向选择
        direction_var = tk.StringVar(value="客户端→服务器")
        direction_combo = ttk.Combobox(frame_row, textvariable=direction_var,
                                      values=["客户端→服务器", "服务器→客户端"],
                                      state="readonly", width=12)
        direction_combo.grid(row=0, column=0, padx=(0, 5))

        # 数据内容输入
        data_var = tk.StringVar(value="Hello World")
        data_entry = ttk.Entry(frame_row, textvariable=data_var, width=40)
        data_entry.grid(row=0, column=1, padx=(0, 5), sticky=(tk.W, tk.E))

        # 数据格式选择
        format_var = tk.StringVar(value="UTF-8")
        format_combo = ttk.Combobox(frame_row, textvariable=format_var,
                                   values=["UTF-8", "十六进制"],
                                   state="readonly", width=8)
        format_combo.grid(row=0, column=2, padx=(0, 5))

        # 删除按钮
        delete_btn = ttk.Button(frame_row, text="删除", width=6,
                               command=lambda: self.remove_data_frame(frame_index))
        delete_btn.grid(row=0, column=3)

        # 保存帧信息
        frame_info = {
            'frame': frame_row,
            'direction': direction_var,
            'data': data_var,
            'format': format_var,
            'delete_btn': delete_btn
        }

        self.data_frames.append(frame_info)

    def remove_data_frame(self, index):
        """删除指定的数据帧"""
        if 0 <= index < len(self.data_frames):
            # 销毁GUI组件
            self.data_frames[index]['frame'].destroy()
            # 从列表中移除
            del self.data_frames[index]
            # 重新排列剩余的帧
            self.refresh_data_frames()

    def clear_data_frames(self):
        """清空所有数据帧"""
        for frame_info in self.data_frames:
            frame_info['frame'].destroy()
        self.data_frames.clear()

    def refresh_data_frames(self):
        """重新排列数据帧显示"""
        for i, frame_info in enumerate(self.data_frames):
            frame_info['frame'].grid(row=i, column=0, sticky=(tk.W, tk.E), pady=2)
            # 更新删除按钮的命令
            frame_info['delete_btn'].configure(command=lambda idx=i: self.remove_data_frame(idx))

    def validate_inputs(self):
        """验证用户输入"""
        try:
            # 验证MAC地址
            if not validate_mac_address(self.src_mac_var.get()):
                raise ValueError("源MAC地址格式无效")
            if not validate_mac_address(self.dst_mac_var.get()):
                raise ValueError("目标MAC地址格式无效")

            # 验证IP地址
            if self.ip_version_var.get() == "IPv4":
                if not validate_ipv4_address(self.src_ip_var.get()):
                    raise ValueError("源IPv4地址格式无效")
                if not validate_ipv4_address(self.dst_ip_var.get()):
                    raise ValueError("目标IPv4地址格式无效")
            else:
                if not validate_ipv6_address(self.src_ip_var.get()):
                    raise ValueError("源IPv6地址格式无效")
                if not validate_ipv6_address(self.dst_ip_var.get()):
                    raise ValueError("目标IPv6地址格式无效")

            # 验证端口
            if not validate_port(self.src_port_var.get()):
                raise ValueError("源端口无效（范围：1-65535）")
            if not validate_port(self.dst_port_var.get()):
                raise ValueError("目标端口无效（范围：1-65535）")

            # 验证数据配置
            if self.protocol_var.get() == "TCP":
                if self.data_mode_var.get() == "简单模式":
                    try:
                        data_size = int(self.data_size_var.get())
                        if data_size <= 0:
                            raise ValueError("数据大小必须大于0")
                    except ValueError:
                        raise ValueError("数据大小必须是有效的正整数")

                    # 检查是否至少有一个数据框有内容
                    c2s_content = self.c2s_data_var.get().strip()
                    s2c_content = self.s2c_data_var.get().strip()
                    if not c2s_content and not s2c_content:
                        raise ValueError("简单模式下至少需要填写一个数据框的内容")

                else:  # 高级模式
                    try:
                        max_frame_size = int(self.max_frame_size_var.get())
                        if max_frame_size <= 0:
                            raise ValueError("最大帧大小必须大于0")
                    except ValueError:
                        raise ValueError("最大帧大小必须是有效的数字")

                    if not self.data_frames:
                        raise ValueError("高级模式下至少需要配置一个数据帧")

            return True

        except ValueError as e:
            messagebox.showerror("输入错误", str(e))
            return False

    def generate_packets(self):
        """生成数据包"""
        if not self.validate_inputs():
            return

        try:
            self.status_var.set("正在生成数据包...")
            self.root.update()

            # 清空之前的包
            self.packet_generator.clear_packets()

            # 创建以太网帧
            src_mac = normalize_mac_address(self.src_mac_var.get())
            dst_mac = normalize_mac_address(self.dst_mac_var.get())
            eth_frame = self.packet_generator.create_ethernet_frame(src_mac, dst_mac)

            # 创建IP层
            ip_version = 4 if self.ip_version_var.get() == "IPv4" else 6
            src_ip = self.src_ip_var.get()
            dst_ip = self.dst_ip_var.get()

            ip_kwargs = {}
            if ip_version == 4:
                ip_kwargs['ttl'] = int(self.ttl_var.get())
                ip_kwargs['tos'] = int(self.tos_var.get())
            else:
                ip_kwargs['hlim'] = int(self.hlim_var.get())
                ip_kwargs['tc'] = int(self.tc_var.get())

            ip_layer = self.packet_generator.create_ip_layer(ip_version, src_ip, dst_ip, **ip_kwargs)

            # 生成传输层数据包
            src_port = int(self.src_port_var.get())
            dst_port = int(self.dst_port_var.get())

            if self.protocol_var.get() == "TCP":
                if self.data_mode_var.get() == "简单模式":
                    packets = self.generate_simple_tcp_packets(
                        eth_frame, ip_layer, src_port, dst_port
                    )
                else:  # 高级模式
                    max_frame_size = int(self.max_frame_size_var.get())
                    packets = self.generate_advanced_tcp_packets(
                        eth_frame, ip_layer, src_port, dst_port, max_frame_size
                    )
            else:  # UDP
                if self.data_mode_var.get() == "简单模式":
                    data_size = int(self.data_size_var.get()) if self.data_size_var.get() else 0
                    packets = self.packet_generator.generate_udp_packets(
                        eth_frame, ip_layer, src_port, dst_port, data_size
                    )
                else:  # UDP高级模式
                    packets = self.generate_advanced_udp_packets(
                        eth_frame, ip_layer, src_port, dst_port
                    )

            self.packet_generator.packets = packets

            self.status_var.set(f"成功生成 {len(packets)} 个数据包")
            self.save_btn.config(state=tk.NORMAL)

        except Exception as e:
            messagebox.showerror("生成错误", f"生成数据包时发生错误：{str(e)}")
            self.status_var.set("生成失败")

    def save_pcap(self):
        """保存PCAP文件"""
        if not self.packet_generator.packets:
            messagebox.showwarning("警告", "没有数据包可保存")
            return

        try:
            filename = filedialog.asksaveasfilename(
                title="保存PCAP文件",
                defaultextension=".pcap",
                filetypes=[("PCAP文件", "*.pcap"), ("所有文件", "*.*")]
            )

            if filename:
                packet_count = self.packet_generator.save_to_pcap(filename)
                self.status_var.set(f"已保存 {packet_count} 个数据包到 {os.path.basename(filename)}")
                messagebox.showinfo("保存成功", f"PCAP文件已保存到：\n{filename}")

        except Exception as e:
            messagebox.showerror("保存错误", f"保存PCAP文件时发生错误：{str(e)}")

    def parse_data_content(self, content, format_type):
        """解析数据内容"""
        if format_type == "UTF-8":
            return content.encode('utf-8')
        elif format_type == "十六进制":
            # 移除空格和分隔符
            hex_str = content.replace(' ', '').replace('-', '').replace(':', '')
            try:
                return bytes.fromhex(hex_str)
            except ValueError:
                raise ValueError(f"无效的十六进制数据: {content}")
        else:
            raise ValueError(f"不支持的数据格式: {format_type}")

    def parse_escape_sequences(self, text):
        """解析转义序列，如\\r\\n转换为实际的回车换行"""
        return text.replace('\\r', '\r').replace('\\n', '\n').replace('\\t', '\t')

    def generate_simple_tcp_packets(self, eth_frame, ip_layer, src_port, dst_port):
        """生成简单模式的TCP数据包"""
        packets = []

        # 创建反向的以太网帧和IP层
        eth_frame_reply = self.packet_generator.create_ethernet_frame(eth_frame.dst, eth_frame.src)
        ip_layer_reply = self.packet_generator.create_ip_layer(
            4 if isinstance(ip_layer, IP) else 6,
            ip_layer.dst, ip_layer.src
        )

        # TCP三次握手
        self.packet_generator.tcp_seq = random.randint(1000, 100000)
        server_seq = random.randint(1000, 100000)

        # 1. SYN
        syn_packet = eth_frame / ip_layer / self.packet_generator.create_tcp_syn(
            src_port, dst_port, self.packet_generator.tcp_seq
        )
        packets.append(syn_packet)

        # 2. SYN-ACK
        syn_ack_packet = eth_frame_reply / ip_layer_reply / self.packet_generator.create_tcp_syn_ack(
            dst_port, src_port, server_seq, self.packet_generator.tcp_seq + 1
        )
        packets.append(syn_ack_packet)

        # 3. ACK
        self.packet_generator.tcp_seq += 1
        self.packet_generator.tcp_ack = server_seq + 1
        ack_packet = eth_frame / ip_layer / self.packet_generator.create_tcp_ack(
            src_port, dst_port, self.packet_generator.tcp_seq, self.packet_generator.tcp_ack
        )
        packets.append(ack_packet)

        # 获取最大帧大小
        max_frame_size = int(self.data_size_var.get()) if self.data_size_var.get() else 1460

        # 4. C2S数据传输
        c2s_content = self.c2s_data_var.get().strip()
        if c2s_content:
            # 解析转义序列
            c2s_content = self.parse_escape_sequences(c2s_content)
            c2s_data = c2s_content.encode('utf-8')

            # 数据分片
            remaining_data = c2s_data
            while remaining_data:
                chunk_size = min(max_frame_size, len(remaining_data))
                chunk_data = remaining_data[:chunk_size]
                remaining_data = remaining_data[chunk_size:]

                # 发送C2S数据包
                data_packet = eth_frame / ip_layer / self.packet_generator.create_tcp_data(
                    src_port, dst_port, self.packet_generator.tcp_seq, self.packet_generator.tcp_ack, chunk_data
                )
                packets.append(data_packet)

                self.packet_generator.tcp_seq += len(chunk_data)

                # 服务器ACK响应
                ack_response = eth_frame_reply / ip_layer_reply / self.packet_generator.create_tcp_ack(
                    dst_port, src_port, self.packet_generator.tcp_ack, self.packet_generator.tcp_seq
                )
                packets.append(ack_response)

        # 5. S2C数据传输
        s2c_content = self.s2c_data_var.get().strip()
        if s2c_content:
            # 解析转义序列
            s2c_content = self.parse_escape_sequences(s2c_content)
            s2c_data = s2c_content.encode('utf-8')

            # 数据分片
            remaining_data = s2c_data
            while remaining_data:
                chunk_size = min(max_frame_size, len(remaining_data))
                chunk_data = remaining_data[:chunk_size]
                remaining_data = remaining_data[chunk_size:]

                # 发送S2C数据包
                data_packet = eth_frame_reply / ip_layer_reply / self.packet_generator.create_tcp_data(
                    dst_port, src_port, self.packet_generator.tcp_ack, self.packet_generator.tcp_seq, chunk_data
                )
                packets.append(data_packet)

                self.packet_generator.tcp_ack += len(chunk_data)

                # 客户端ACK响应
                ack_response = eth_frame / ip_layer / self.packet_generator.create_tcp_ack(
                    src_port, dst_port, self.packet_generator.tcp_seq, self.packet_generator.tcp_ack
                )
                packets.append(ack_response)

        return packets

    def generate_advanced_tcp_packets(self, eth_frame, ip_layer, src_port, dst_port, max_frame_size):
        """生成高级模式的TCP数据包"""
        packets = []

        # 创建反向的以太网帧和IP层
        eth_frame_reply = self.packet_generator.create_ethernet_frame(eth_frame.dst, eth_frame.src)
        ip_layer_reply = self.packet_generator.create_ip_layer(
            4 if isinstance(ip_layer, IP) else 6,
            ip_layer.dst, ip_layer.src
        )

        # TCP三次握手
        self.packet_generator.tcp_seq = random.randint(1000, 100000)
        server_seq = random.randint(1000, 100000)

        # 1. SYN
        syn_packet = eth_frame / ip_layer / self.packet_generator.create_tcp_syn(
            src_port, dst_port, self.packet_generator.tcp_seq
        )
        packets.append(syn_packet)

        # 2. SYN-ACK
        syn_ack_packet = eth_frame_reply / ip_layer_reply / self.packet_generator.create_tcp_syn_ack(
            dst_port, src_port, server_seq, self.packet_generator.tcp_seq + 1
        )
        packets.append(syn_ack_packet)

        # 3. ACK
        self.packet_generator.tcp_seq += 1
        self.packet_generator.tcp_ack = server_seq + 1
        ack_packet = eth_frame / ip_layer / self.packet_generator.create_tcp_ack(
            src_port, dst_port, self.packet_generator.tcp_seq, self.packet_generator.tcp_ack
        )
        packets.append(ack_packet)

        # 4. 数据传输
        for frame_info in self.data_frames:
            direction = frame_info['direction'].get()
            content = frame_info['data'].get()
            format_type = frame_info['format'].get()

            if not content.strip():
                continue

            try:
                data_bytes = self.parse_data_content(content, format_type)
            except ValueError as e:
                raise ValueError(f"数据帧解析错误: {e}")

            # 根据方向选择帧和端口
            if direction == "客户端→服务器":
                send_eth = eth_frame
                send_ip = ip_layer
                send_src_port = src_port
                send_dst_port = dst_port
                reply_eth = eth_frame_reply
                reply_ip = ip_layer_reply
                reply_src_port = dst_port
                reply_dst_port = src_port
                current_seq = self.packet_generator.tcp_seq
                current_ack = self.packet_generator.tcp_ack
            else:  # 服务器→客户端
                send_eth = eth_frame_reply
                send_ip = ip_layer_reply
                send_src_port = dst_port
                send_dst_port = src_port
                reply_eth = eth_frame
                reply_ip = ip_layer
                reply_src_port = src_port
                reply_dst_port = dst_port
                current_seq = self.packet_generator.tcp_ack
                current_ack = self.packet_generator.tcp_seq

            # 数据分片
            remaining_data = data_bytes
            while remaining_data:
                chunk_size = min(max_frame_size, len(remaining_data))
                chunk_data = remaining_data[:chunk_size]
                remaining_data = remaining_data[chunk_size:]

                # 发送数据包
                data_packet = send_eth / send_ip / self.packet_generator.create_tcp_data(
                    send_src_port, send_dst_port, current_seq, current_ack, chunk_data
                )
                packets.append(data_packet)

                # 更新序列号
                if direction == "客户端→服务器":
                    self.packet_generator.tcp_seq += len(chunk_data)
                else:
                    self.packet_generator.tcp_ack += len(chunk_data)

                # 生成ACK响应
                ack_response = reply_eth / reply_ip / self.packet_generator.create_tcp_ack(
                    reply_src_port, reply_dst_port,
                    current_ack if direction == "客户端→服务器" else current_seq + len(chunk_data),
                    current_seq + len(chunk_data) if direction == "客户端→服务器" else current_ack
                )
                packets.append(ack_response)

                current_seq += len(chunk_data)

        return packets

    def generate_advanced_udp_packets(self, eth_frame, ip_layer, src_port, dst_port):
        """生成高级模式的UDP数据包"""
        packets = []

        # 创建反向的以太网帧和IP层
        eth_frame_reply = self.packet_generator.create_ethernet_frame(eth_frame.dst, eth_frame.src)
        ip_layer_reply = self.packet_generator.create_ip_layer(
            4 if isinstance(ip_layer, IP) else 6,
            ip_layer.dst, ip_layer.src
        )

        for frame_info in self.data_frames:
            direction = frame_info['direction'].get()
            content = frame_info['data'].get()
            format_type = frame_info['format'].get()

            if not content.strip():
                continue

            try:
                data_bytes = self.parse_data_content(content, format_type)
            except ValueError as e:
                raise ValueError(f"数据帧解析错误: {e}")

            # 根据方向选择帧和端口
            if direction == "客户端→服务器":
                send_eth = eth_frame
                send_ip = ip_layer
                send_src_port = src_port
                send_dst_port = dst_port
            else:  # 服务器→客户端
                send_eth = eth_frame_reply
                send_ip = ip_layer_reply
                send_src_port = dst_port
                send_dst_port = src_port

            # 创建UDP包
            udp_packet = send_eth / send_ip / self.packet_generator.create_udp_packet(
                send_src_port, send_dst_port, data_bytes
            )
            packets.append(udp_packet)

        return packets

    def run(self):
        """运行GUI应用"""
        self.root.mainloop()
