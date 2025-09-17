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
        self.root.title("PCAP生成工具 v2.1 - 支持数据包预览")
        self.root.geometry("900x1000")
        self.root.resizable(True, True)
        
        # 设置窗口图标（如果有的话）
        try:
            self.root.iconbitmap('icon.ico')
        except:
            pass
            
        self.packet_generator = PacketGenerator()

        # 初始化错误信息存储
        self.last_rebuild_error = None

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

        # UDP配置
        self.udp_frame = ttk.Frame(transport_frame)
        self.udp_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        self.setup_udp_config()
        
        # 生成和保存按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=row, column=0, columnspan=2, pady=(20, 0))
        row += 1

        self.load_btn = ttk.Button(button_frame, text="读取PCAP文件", command=self.load_pcap)
        self.load_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.generate_btn = ttk.Button(button_frame, text="生成数据包", command=self.generate_packets)
        self.generate_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.save_btn = ttk.Button(button_frame, text="保存PCAP文件", command=self.save_pcap, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.preview_btn = ttk.Button(button_frame, text="预览数据包", command=self.preview_packets, state=tk.DISABLED)
        self.preview_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.edit_btn = ttk.Button(button_frame, text="编辑数据包", command=self.edit_packets, state=tk.DISABLED)
        self.edit_btn.pack(side=tk.LEFT)

        # 状态显示
        self.status_var = tk.StringVar(value="就绪")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, foreground="blue")
        status_label.grid(row=row, column=0, columnspan=2, pady=(10, 0))

        # 数据包预览区域
        preview_frame = ttk.LabelFrame(main_frame, text="数据包预览", padding="10")
        preview_frame.grid(row=row+1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        preview_frame.columnconfigure(0, weight=1)
        preview_frame.rowconfigure(0, weight=1)

        # 创建Treeview用于显示数据包列表
        columns = ("序号", "协议", "源地址", "目标地址", "长度", "信息")
        self.packet_tree = ttk.Treeview(preview_frame, columns=columns, show="headings", height=8)

        # 设置列标题和宽度
        self.packet_tree.heading("序号", text="序号")
        self.packet_tree.heading("协议", text="协议")
        self.packet_tree.heading("源地址", text="源地址")
        self.packet_tree.heading("目标地址", text="目标地址")
        self.packet_tree.heading("长度", text="长度")
        self.packet_tree.heading("信息", text="信息")

        self.packet_tree.column("序号", width=50, anchor=tk.CENTER)
        self.packet_tree.column("协议", width=80, anchor=tk.CENTER)
        self.packet_tree.column("源地址", width=120, anchor=tk.CENTER)
        self.packet_tree.column("目标地址", width=120, anchor=tk.CENTER)
        self.packet_tree.column("长度", width=60, anchor=tk.CENTER)
        self.packet_tree.column("信息", width=300, anchor=tk.W)

        # 添加滚动条
        packet_scrollbar = ttk.Scrollbar(preview_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=packet_scrollbar.set)

        # 布局
        self.packet_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        packet_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # 绑定双击事件
        self.packet_tree.bind("<Double-1>", self.on_packet_double_click)

        # 配置主窗口网格权重
        main_frame.rowconfigure(row+1, weight=1)
        
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
            self.udp_frame.grid_remove()
        else:  # UDP
            self.tcp_frame.grid_remove()
            self.udp_frame.grid()

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

    def setup_udp_config(self):
        """设置UDP配置界面"""
        # 数据配置模式选择
        ttk.Label(self.udp_frame, text="数据配置模式:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.udp_data_mode_var = tk.StringVar(value="简单模式")
        udp_mode_combo = ttk.Combobox(self.udp_frame, textvariable=self.udp_data_mode_var,
                                     values=["简单模式", "高级模式"], state="readonly", width=12)
        udp_mode_combo.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        udp_mode_combo.bind('<<ComboboxSelected>>', self.on_udp_data_mode_change)

        # 简单模式配置
        self.udp_simple_data_frame = ttk.Frame(self.udp_frame)
        self.udp_simple_data_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        self.udp_simple_data_frame.columnconfigure(1, weight=1)

        # C2S数据配置
        udp_c2s_frame = ttk.LabelFrame(self.udp_simple_data_frame, text="客户端→服务器数据 (C2S)", padding="5")
        udp_c2s_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        udp_c2s_frame.columnconfigure(1, weight=1)

        ttk.Label(udp_c2s_frame, text="UTF-8内容:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.udp_c2s_data_var = tk.StringVar(value="DNS Query: example.com")
        self.udp_c2s_data_entry = ttk.Entry(udp_c2s_frame, textvariable=self.udp_c2s_data_var, width=50)
        self.udp_c2s_data_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        # S2C数据配置
        udp_s2c_frame = ttk.LabelFrame(self.udp_simple_data_frame, text="服务器→客户端数据 (S2C)", padding="5")
        udp_s2c_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        udp_s2c_frame.columnconfigure(1, weight=1)

        ttk.Label(udp_s2c_frame, text="UTF-8内容:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.udp_s2c_data_var = tk.StringVar(value="DNS Response: 93.184.216.34")
        self.udp_s2c_data_entry = ttk.Entry(udp_s2c_frame, textvariable=self.udp_s2c_data_var, width=50)
        self.udp_s2c_data_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        # 高级模式配置
        self.udp_advanced_data_frame = ttk.Frame(self.udp_frame)
        self.udp_advanced_data_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        self.setup_udp_advanced_data_config()

        # 初始隐藏UDP框架和高级模式
        self.udp_frame.grid_remove()
        self.udp_advanced_data_frame.grid_remove()

    def setup_udp_advanced_data_config(self):
        """设置UDP高级数据配置界面"""
        # 数据帧列表
        list_frame = ttk.LabelFrame(self.udp_advanced_data_frame, text="UDP数据帧配置", padding="5")
        list_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        list_frame.columnconfigure(0, weight=1)

        # 列表头部
        header_frame = ttk.Frame(list_frame)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        header_frame.columnconfigure(1, weight=1)

        ttk.Label(header_frame, text="方向", width=8).grid(row=0, column=0, padx=(0, 5))
        ttk.Label(header_frame, text="数据内容", width=30).grid(row=0, column=1, padx=(0, 5))
        ttk.Label(header_frame, text="格式", width=8).grid(row=0, column=2, padx=(0, 5))
        ttk.Label(header_frame, text="操作", width=8).grid(row=0, column=3)

        # UDP数据帧列表容器
        self.udp_frames_container = ttk.Frame(list_frame)
        self.udp_frames_container.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.udp_frames_container.columnconfigure(1, weight=1)

        # UDP数据帧列表
        self.udp_data_frames = []

        # 添加按钮
        udp_add_frame = ttk.Frame(list_frame)
        udp_add_frame.grid(row=2, column=0, sticky=tk.W, pady=(5, 0))

        ttk.Button(udp_add_frame, text="添加帧", command=self.add_udp_data_frame).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(udp_add_frame, text="清空所有", command=self.clear_udp_data_frames).pack(side=tk.LEFT)

        # 默认添加一个UDP数据帧
        self.add_udp_data_frame()

    def on_udp_data_mode_change(self, event=None):
        """UDP数据配置模式改变时的处理"""
        if self.udp_data_mode_var.get() == "简单模式":
            self.udp_simple_data_frame.grid()
            self.udp_advanced_data_frame.grid_remove()
        else:
            self.udp_simple_data_frame.grid_remove()
            self.udp_advanced_data_frame.grid()

    def add_udp_data_frame(self):
        """添加一个UDP数据帧配置行"""
        frame_index = len(self.udp_data_frames)

        # 创建帧配置行
        frame_row = ttk.Frame(self.udp_frames_container)
        frame_row.grid(row=frame_index, column=0, sticky=(tk.W, tk.E), pady=2)
        frame_row.columnconfigure(1, weight=1)

        # 方向选择
        direction_var = tk.StringVar(value="客户端→服务器")
        direction_combo = ttk.Combobox(frame_row, textvariable=direction_var,
                                      values=["客户端→服务器", "服务器→客户端"],
                                      state="readonly", width=12)
        direction_combo.grid(row=0, column=0, padx=(0, 5))

        # 数据内容输入
        data_var = tk.StringVar(value="UDP Data")
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
                               command=lambda: self.remove_udp_data_frame(frame_index))
        delete_btn.grid(row=0, column=3)

        # 保存帧信息
        frame_info = {
            'frame': frame_row,
            'direction': direction_var,
            'data': data_var,
            'format': format_var,
            'delete_btn': delete_btn
        }

        self.udp_data_frames.append(frame_info)

    def remove_udp_data_frame(self, index):
        """删除指定的UDP数据帧"""
        if 0 <= index < len(self.udp_data_frames):
            # 销毁GUI组件
            self.udp_data_frames[index]['frame'].destroy()
            # 从列表中移除
            del self.udp_data_frames[index]
            # 重新排列剩余的帧
            self.refresh_udp_data_frames()

    def clear_udp_data_frames(self):
        """清空所有UDP数据帧"""
        for frame_info in self.udp_data_frames:
            frame_info['frame'].destroy()
        self.udp_data_frames.clear()

    def refresh_udp_data_frames(self):
        """重新排列UDP数据帧显示"""
        for i, frame_info in enumerate(self.udp_data_frames):
            frame_info['frame'].grid(row=i, column=0, sticky=(tk.W, tk.E), pady=2)
            # 更新删除按钮的命令
            frame_info['delete_btn'].configure(command=lambda idx=i: self.remove_udp_data_frame(idx))

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
            else:  # UDP验证
                if self.udp_data_mode_var.get() == "简单模式":
                    # 检查是否至少有一个UDP数据框有内容
                    c2s_content = self.udp_c2s_data_var.get().strip()
                    s2c_content = self.udp_s2c_data_var.get().strip()
                    if not c2s_content and not s2c_content:
                        raise ValueError("UDP简单模式下至少需要填写一个数据框的内容")
                else:  # UDP高级模式
                    if not self.udp_data_frames:
                        raise ValueError("UDP高级模式下至少需要配置一个数据帧")

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
                # 确保IPv6参数存在，如果不存在则使用默认值
                if hasattr(self, 'hlim_var'):
                    ip_kwargs['hlim'] = int(self.hlim_var.get())
                else:
                    ip_kwargs['hlim'] = 64  # 默认跳数限制

                if hasattr(self, 'tc_var'):
                    ip_kwargs['tc'] = int(self.tc_var.get())
                else:
                    ip_kwargs['tc'] = 0  # 默认流量类别

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
                if self.udp_data_mode_var.get() == "简单模式":
                    packets = self.generate_simple_udp_packets(
                        eth_frame, ip_layer, src_port, dst_port
                    )
                else:  # UDP高级模式
                    packets = self.generate_advanced_udp_packets_new(
                        eth_frame, ip_layer, src_port, dst_port
                    )

            self.packet_generator.packets = packets

            self.status_var.set(f"成功生成 {len(packets)} 个数据包")
            self.save_btn.config(state=tk.NORMAL)
            self.preview_btn.config(state=tk.NORMAL)
            self.edit_btn.config(state=tk.NORMAL)

            # 自动显示预览
            self.update_packet_preview()

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
        last_direction = None
        for i, frame_info in enumerate(self.data_frames):
            direction = frame_info['direction'].get()
            content = frame_info['data'].get()
            format_type = frame_info['format'].get()

            if not content.strip():
                continue

            try:
                data_bytes = self.parse_data_content(content, format_type)
            except ValueError as e:
                raise ValueError(f"数据帧解析错误: {e}")

            # 检查是否需要生成ACK（连续两包方向相反）
            need_ack_before = (last_direction is not None and
                              last_direction != direction and
                              len(packets) > 3)  # 确保握手已完成

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

            # 如果方向改变，先生成前一个方向的ACK
            if need_ack_before:
                if last_direction == "客户端→服务器":
                    # 服务器发送ACK
                    ack_packet = eth_frame_reply / ip_layer_reply / self.packet_generator.create_tcp_ack(
                        dst_port, src_port, self.packet_generator.tcp_ack, self.packet_generator.tcp_seq
                    )
                else:
                    # 客户端发送ACK
                    ack_packet = eth_frame / ip_layer / self.packet_generator.create_tcp_ack(
                        src_port, dst_port, self.packet_generator.tcp_seq, self.packet_generator.tcp_ack
                    )
                packets.append(ack_packet)

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

                current_seq += len(chunk_data)

            # 记录当前方向
            last_direction = direction

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

    def generate_simple_udp_packets(self, eth_frame, ip_layer, src_port, dst_port):
        """生成简单模式的UDP数据包"""
        packets = []

        # 创建反向的以太网帧和IP层
        eth_frame_reply = self.packet_generator.create_ethernet_frame(eth_frame.dst, eth_frame.src)
        ip_layer_reply = self.packet_generator.create_ip_layer(
            4 if isinstance(ip_layer, IP) else 6,
            ip_layer.dst, ip_layer.src
        )

        # C2S数据传输
        c2s_content = self.udp_c2s_data_var.get().strip()
        if c2s_content:
            # 解析转义序列
            c2s_content = self.parse_escape_sequences(c2s_content)
            c2s_data = c2s_content.encode('utf-8')

            # 创建C2S UDP包
            udp_packet = eth_frame / ip_layer / self.packet_generator.create_udp_packet(
                src_port, dst_port, c2s_data
            )
            packets.append(udp_packet)

        # S2C数据传输
        s2c_content = self.udp_s2c_data_var.get().strip()
        if s2c_content:
            # 解析转义序列
            s2c_content = self.parse_escape_sequences(s2c_content)
            s2c_data = s2c_content.encode('utf-8')

            # 创建S2C UDP包
            udp_packet = eth_frame_reply / ip_layer_reply / self.packet_generator.create_udp_packet(
                dst_port, src_port, s2c_data
            )
            packets.append(udp_packet)

        return packets

    def generate_advanced_udp_packets_new(self, eth_frame, ip_layer, src_port, dst_port):
        """生成高级模式的UDP数据包（新版本）"""
        packets = []

        # 创建反向的以太网帧和IP层
        eth_frame_reply = self.packet_generator.create_ethernet_frame(eth_frame.dst, eth_frame.src)
        ip_layer_reply = self.packet_generator.create_ip_layer(
            4 if isinstance(ip_layer, IP) else 6,
            ip_layer.dst, ip_layer.src
        )

        for frame_info in self.udp_data_frames:
            direction = frame_info['direction'].get()
            content = frame_info['data'].get()
            format_type = frame_info['format'].get()

            if not content.strip():
                continue

            try:
                data_bytes = self.parse_data_content(content, format_type)
            except ValueError as e:
                raise ValueError(f"UDP数据帧解析错误: {e}")

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

    def analyze_packet(self, packet):
        """分析数据包并返回详细信息"""
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.l2 import Ether

            # 添加调试信息
            debug_analyze = True  # 设置为True启用调试
            if debug_analyze:
                print(f"    [analyze_packet] 分析数据包: {type(packet)}")
                try:
                    # 使用packet.show()来获取层信息
                    import io
                    import sys
                    old_stdout = sys.stdout
                    sys.stdout = buffer = io.StringIO()
                    packet.show()
                    sys.stdout = old_stdout
                    packet_info = buffer.getvalue()
                    print(f"    [analyze_packet] 数据包结构:\n{packet_info}")
                except:
                    print(f"    [analyze_packet] 无法获取层信息")

                if IP in packet:
                    print(f"    [analyze_packet] 发现IPv4层: {packet[IP].src} → {packet[IP].dst}")
                if IPv6 in packet:
                    print(f"    [analyze_packet] 发现IPv6层: {packet[IPv6].src} → {packet[IPv6].dst}")

                # 检查数据包的实际内容
                print(f"    [analyze_packet] 数据包摘要: {packet.summary()}")
                print(f"    [analyze_packet] 数据包ID: {id(packet)}")

            info = {
                'protocol': 'Unknown',
                'src_addr': '',
                'dst_addr': '',
                'length': len(packet),
                'summary': ''
            }

            # 分析以太网层
            if Ether in packet:
                eth = packet[Ether]
                info['src_addr'] = eth.src
                info['dst_addr'] = eth.dst

            # 分析IP层 - 优先检查IPv6
            if IPv6 in packet:
                ipv6 = packet[IPv6]
                info['src_addr'] = f"{info['src_addr']} ({ipv6.src})"
                info['dst_addr'] = f"{info['dst_addr']} ({ipv6.dst})"

                if TCP in packet:
                    tcp = packet[TCP]
                    info['protocol'] = 'IPv6 TCP'  # 明确标识为IPv6 TCP
                    info['src_addr'] += f":{tcp.sport}"
                    info['dst_addr'] += f":{tcp.dport}"

                    flags = []
                    if tcp.flags & 0x01: flags.append('FIN')
                    if tcp.flags & 0x02: flags.append('SYN')
                    if tcp.flags & 0x04: flags.append('RST')
                    if tcp.flags & 0x08: flags.append('PSH')
                    if tcp.flags & 0x10: flags.append('ACK')
                    if tcp.flags & 0x20: flags.append('URG')

                    flag_str = ','.join(flags) if flags else 'None'
                    data_len = len(tcp.payload) if tcp.payload else 0
                    info['summary'] = f"Flags=[{flag_str}] Seq={tcp.seq} Ack={tcp.ack} Len={data_len}"

                elif UDP in packet:
                    udp = packet[UDP]
                    info['protocol'] = 'IPv6 UDP'  # 明确标识为IPv6 UDP
                    info['src_addr'] += f":{udp.sport}"
                    info['dst_addr'] += f":{udp.dport}"

                    data_len = len(udp.payload) if udp.payload else 0
                    info['summary'] = f"Len={data_len}"
                else:
                    info['protocol'] = 'IPv6'  # 纯IPv6数据包

            elif IP in packet:
                ip = packet[IP]
                info['src_addr'] = f"{info['src_addr']} ({ip.src})"
                info['dst_addr'] = f"{info['dst_addr']} ({ip.dst})"

                # 分析传输层
                if TCP in packet:
                    tcp = packet[TCP]
                    info['protocol'] = 'IPv4 TCP'  # 明确标识为IPv4 TCP
                    info['src_addr'] += f":{tcp.sport}"
                    info['dst_addr'] += f":{tcp.dport}"

                    # TCP标志位分析
                    flags = []
                    if tcp.flags & 0x01: flags.append('FIN')
                    if tcp.flags & 0x02: flags.append('SYN')
                    if tcp.flags & 0x04: flags.append('RST')
                    if tcp.flags & 0x08: flags.append('PSH')
                    if tcp.flags & 0x10: flags.append('ACK')
                    if tcp.flags & 0x20: flags.append('URG')

                    flag_str = ','.join(flags) if flags else 'None'
                    data_len = len(tcp.payload) if tcp.payload else 0
                    info['summary'] = f"Flags=[{flag_str}] Seq={tcp.seq} Ack={tcp.ack} Len={data_len}"

                elif UDP in packet:
                    udp = packet[UDP]
                    info['protocol'] = 'IPv4 UDP'  # 明确标识为IPv4 UDP
                    info['src_addr'] += f":{udp.sport}"
                    info['dst_addr'] += f":{udp.dport}"

                    data_len = len(udp.payload) if udp.payload else 0
                    info['summary'] = f"Len={data_len}"
                else:
                    info['protocol'] = 'IPv4'  # 纯IPv4数据包

            return info

        except Exception as e:
            return {
                'protocol': 'Error',
                'src_addr': '',
                'dst_addr': '',
                'length': len(packet),
                'summary': f'分析错误: {str(e)}'
            }

    def update_packet_preview(self):
        """更新数据包预览列表"""
        print("=== 更新主窗口数据包预览 ===")
        print(f"当前数据包总数: {len(self.packet_generator.packets)}")

        # 清空现有项目
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

        if not self.packet_generator.packets:
            print("没有数据包可显示")
            return

        # 显示前5个数据包的详细信息
        for i, packet in enumerate(self.packet_generator.packets[:5], 1):
            # 添加详细调试信息
            from scapy.layers.inet import IP
            from scapy.layers.inet6 import IPv6

            print(f"  [主窗口预览] 数据包 {i} 调试:")
            print(f"    类型: {type(packet)}")
            print(f"    包含IPv4: {IP in packet}")
            print(f"    包含IPv6: {IPv6 in packet}")
            if IP in packet:
                print(f"    IPv4地址: {packet[IP].src} → {packet[IP].dst}")
            if IPv6 in packet:
                print(f"    IPv6地址: {packet[IPv6].src} → {packet[IPv6].dst}")

            info = self.analyze_packet(packet)
            self.packet_tree.insert('', 'end', values=(
                i,
                info['protocol'],
                info['src_addr'],
                info['dst_addr'],
                info['length'],
                info['summary']
            ))
            print(f"    分析结果: {info['protocol']} - {info['src_addr']} → {info['dst_addr']}")

        # 添加剩余数据包但不打印详细信息
        if len(self.packet_generator.packets) > 5:
            for i, packet in enumerate(self.packet_generator.packets[5:], 6):
                info = self.analyze_packet(packet)
                self.packet_tree.insert('', 'end', values=(
                    i,
                    info['protocol'],
                    info['src_addr'],
                    info['dst_addr'],
                    info['length'],
                    info['summary']
                ))
            print(f"  ... 还有 {len(self.packet_generator.packets) - 5} 个数据包")

        print("=== 主窗口数据包预览更新完成 ===")

    def preview_packets(self):
        """预览数据包按钮点击事件"""
        if not self.packet_generator.packets:
            messagebox.showwarning("警告", "没有数据包可预览")
            return

        self.update_packet_preview()
        messagebox.showinfo("预览", f"已显示 {len(self.packet_generator.packets)} 个数据包的详细信息")

    def on_packet_double_click(self, event):
        """双击数据包事件处理"""
        selection = self.packet_tree.selection()
        if not selection:
            return

        item = self.packet_tree.item(selection[0])
        packet_index = int(item['values'][0]) - 1

        if 0 <= packet_index < len(self.packet_generator.packets):
            self.show_packet_details(packet_index)

    def show_packet_details(self, packet_index):
        """显示数据包详细信息"""
        packet = self.packet_generator.packets[packet_index]

        # 创建详细信息窗口
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"数据包 #{packet_index + 1} 详细信息")
        detail_window.geometry("600x500")
        detail_window.resizable(True, True)

        # 创建文本框显示详细信息
        text_frame = ttk.Frame(detail_window, padding="10")
        text_frame.pack(fill=tk.BOTH, expand=True)

        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=("Consolas", 10))
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)

        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 获取数据包详细信息
        try:
            # 获取协议层分析
            packet_info = packet.show(dump=True)

            # 获取十六进制转储
            try:
                hex_dump = packet.hexdump(dump=True)
            except:
                # 如果hexdump失败，手动生成十六进制显示
                packet_bytes = bytes(packet)
                hex_lines = []
                for i in range(0, len(packet_bytes), 16):
                    chunk = packet_bytes[i:i+16]
                    hex_part = ' '.join(f'{b:02x}' for b in chunk)
                    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                    hex_lines.append(f'{i:04x}  {hex_part:<48} {ascii_part}')
                hex_dump = '\n'.join(hex_lines)

            detail_text = f"数据包 #{packet_index + 1} 详细信息\n"
            detail_text += "=" * 50 + "\n\n"
            detail_text += "协议层分析:\n"
            detail_text += "-" * 20 + "\n"
            detail_text += packet_info + "\n\n"
            detail_text += "十六进制转储:\n"
            detail_text += "-" * 20 + "\n"
            detail_text += hex_dump

            text_widget.insert(tk.END, detail_text)
            text_widget.config(state=tk.DISABLED)

        except Exception as e:
            # 如果所有方法都失败，至少显示基本信息
            try:
                packet_bytes = bytes(packet)
                basic_info = f"数据包 #{packet_index + 1} 基本信息\n"
                basic_info += "=" * 50 + "\n\n"
                basic_info += f"数据包长度: {len(packet_bytes)} 字节\n"
                basic_info += f"数据包类型: {type(packet).__name__}\n\n"
                basic_info += "原始字节数据:\n"
                basic_info += "-" * 20 + "\n"

                # 手动生成十六进制显示
                for i in range(0, len(packet_bytes), 16):
                    chunk = packet_bytes[i:i+16]
                    hex_part = ' '.join(f'{b:02x}' for b in chunk)
                    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                    basic_info += f'{i:04x}  {hex_part:<48} {ascii_part}\n'

                text_widget.insert(tk.END, basic_info)
                text_widget.config(state=tk.DISABLED)
            except Exception as e2:
                text_widget.insert(tk.END, f"无法显示数据包详细信息: {str(e)}\n详细错误: {str(e2)}")
                text_widget.config(state=tk.DISABLED)

        # 添加关闭按钮
        button_frame = ttk.Frame(detail_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(button_frame, text="关闭", command=detail_window.destroy).pack(side=tk.RIGHT)

    def load_pcap(self):
        """读取PCAP文件"""
        try:
            filename = filedialog.askopenfilename(
                title="选择PCAP文件",
                filetypes=[("PCAP文件", "*.pcap"), ("PCAPNG文件", "*.pcapng"), ("所有文件", "*.*")]
            )

            if filename:
                from scapy.all import rdpcap

                # 读取PCAP文件
                packets = rdpcap(filename)
                # 将PacketList转换为普通列表以支持项目赋值
                self.packet_generator.packets = list(packets)

                # 更新预览
                self.update_packet_preview()

                # 启用相关按钮
                self.save_btn.config(state=tk.NORMAL)
                self.preview_btn.config(state=tk.NORMAL)
                self.edit_btn.config(state=tk.NORMAL)

                self.status_var.set(f"成功读取 {len(packets)} 个数据包从 {os.path.basename(filename)}")

        except Exception as e:
            messagebox.showerror("读取错误", f"读取PCAP文件时发生错误：{str(e)}")
            self.status_var.set("读取失败")

    def edit_packets(self):
        """编辑数据包"""
        if not self.packet_generator.packets:
            messagebox.showwarning("警告", "没有数据包可编辑")
            return

        # 创建编辑窗口
        self.create_packet_editor()

    def create_packet_editor(self):
        """创建数据包编辑器窗口"""
        editor_window = tk.Toplevel(self.root)
        editor_window.title("数据包编辑器")
        editor_window.geometry("1000x700")
        editor_window.resizable(True, True)

        # 创建主框架
        main_frame = ttk.Frame(editor_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 左侧：数据包列表
        left_frame = ttk.LabelFrame(main_frame, text="数据包列表", padding="5")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 10))

        # 数据包列表
        packet_listbox = tk.Listbox(left_frame, width=30, height=25)
        packet_scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=packet_listbox.yview)
        packet_listbox.configure(yscrollcommand=packet_scrollbar.set)

        packet_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        packet_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 存储编辑器窗口的引用，以便后续更新
        self.editor_window = editor_window
        self.editor_packet_listbox = packet_listbox

        # 定义刷新数据包列表的函数
        def refresh_packet_list():
            """刷新数据包列表"""
            print("=== 刷新编辑器数据包列表 ===")
            print(f"当前数据包总数: {len(self.packet_generator.packets)}")

            packet_listbox.delete(0, tk.END)

            # 显示前5个数据包的详细信息
            for i, packet in enumerate(self.packet_generator.packets[:5], 1):
                # 添加详细调试信息
                from scapy.layers.inet import IP
                from scapy.layers.inet6 import IPv6

                print(f"  [编辑器刷新] 数据包 {i} 调试:")
                print(f"    类型: {type(packet)}")
                print(f"    包含IPv4: {IP in packet}")
                print(f"    包含IPv6: {IPv6 in packet}")
                if IP in packet:
                    print(f"    IPv4地址: {packet[IP].src} → {packet[IP].dst}")
                if IPv6 in packet:
                    print(f"    IPv6地址: {packet[IPv6].src} → {packet[IPv6].dst}")

                info = self.analyze_packet(packet)
                packet_listbox.insert(tk.END, f"{i:3d}. {info['protocol']} - {info['summary'][:30]}")
                print(f"    分析结果: {info['protocol']} - {info['src_addr']} → {info['dst_addr']}")

            # 如果有更多数据包，继续添加但不打印详细信息
            if len(self.packet_generator.packets) > 5:
                for i, packet in enumerate(self.packet_generator.packets[5:], 6):
                    info = self.analyze_packet(packet)
                    packet_listbox.insert(tk.END, f"{i:3d}. {info['protocol']} - {info['summary'][:30]}")

                print(f"  ... 还有 {len(self.packet_generator.packets) - 5} 个数据包")

            print("=== 编辑器数据包列表刷新完成 ===")

        # 存储刷新函数的引用
        self.refresh_editor_packet_list = refresh_packet_list

        # 初始填充数据包列表
        refresh_packet_list()

        # 右侧：数据包编辑区域
        right_frame = ttk.LabelFrame(main_frame, text="数据包编辑", padding="5")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # 当前选中的数据包索引
        self.current_packet_index = tk.IntVar(value=0)

        # 绑定列表选择事件
        def on_packet_select(event):
            selection = packet_listbox.curselection()
            if selection:
                self.current_packet_index.set(selection[0])
                self.load_packet_for_editing(right_frame, selection[0])

        packet_listbox.bind('<<ListboxSelect>>', on_packet_select)

        # 初始加载第一个数据包
        if self.packet_generator.packets:
            packet_listbox.selection_set(0)
            self.load_packet_for_editing(right_frame, 0)

        # 底部按钮
        button_frame = ttk.Frame(editor_window)
        button_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(button_frame, text="应用修改", command=lambda: self.apply_packet_changes(right_frame)).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="重置", command=lambda: self.load_packet_for_editing(right_frame, self.current_packet_index.get())).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="简单IP转换", command=lambda: self.simple_ip_conversion_dialog(editor_window)).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="关闭", command=editor_window.destroy).pack(side=tk.RIGHT)

    def load_packet_for_editing(self, parent_frame, packet_index):
        """加载数据包进行编辑"""
        # 清空现有内容
        for widget in parent_frame.winfo_children():
            widget.destroy()

        if packet_index >= len(self.packet_generator.packets):
            return

        packet = self.packet_generator.packets[packet_index]

        # 创建滚动区域
        canvas = tk.Canvas(parent_frame)
        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # 存储编辑字段的引用
        self.edit_fields = {}

        # 分析数据包的各层
        self.create_layer_editors(scrollable_frame, packet, packet_index)

        # 布局
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def create_layer_editors(self, parent, packet, packet_index):
        """创建各层的编辑器"""
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Ether

        layer_count = 0

        # 以太网层
        if Ether in packet:
            self.create_ethernet_editor(parent, packet[Ether], layer_count)
            layer_count += 1

        # IP层
        if IP in packet:
            self.create_ipv4_editor(parent, packet[IP], layer_count)
            layer_count += 1
        elif IPv6 in packet:
            self.create_ipv6_editor(parent, packet[IPv6], layer_count)
            layer_count += 1

        # 传输层
        if TCP in packet:
            self.create_tcp_editor(parent, packet[TCP], layer_count)
            layer_count += 1
        elif UDP in packet:
            self.create_udp_editor(parent, packet[UDP], layer_count)
            layer_count += 1

        # 应用层数据
        payload = self.get_payload_data(packet)
        if payload:
            self.create_payload_editor(parent, payload, layer_count)
            layer_count += 1

        # Trailer数据 - 所有数据包都显示trailer区域
        trailer_info = self.detect_packet_trailer(packet)
        if not trailer_info:
            # 如果没有检测到trailer，创建一个空的trailer信息
            trailer_info = {
                'type': 'none',
                'data': b'',
                'description': '无尾部数据'
            }
        self.create_trailer_editor(parent, trailer_info, layer_count)

    def create_ethernet_editor(self, parent, eth_layer, layer_index):
        """创建以太网层编辑器"""
        frame = ttk.LabelFrame(parent, text="以太网层 (Ethernet)", padding="10")
        frame.pack(fill=tk.X, padx=5, pady=5)
        frame.columnconfigure(1, weight=1)

        # 源MAC地址
        ttk.Label(frame, text="源MAC地址:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        src_mac_var = tk.StringVar(value=eth_layer.src)
        ttk.Entry(frame, textvariable=src_mac_var, width=20).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        self.edit_fields[f'eth_{layer_index}_src'] = src_mac_var

        # 目标MAC地址
        ttk.Label(frame, text="目标MAC地址:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        dst_mac_var = tk.StringVar(value=eth_layer.dst)
        ttk.Entry(frame, textvariable=dst_mac_var, width=20).grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        self.edit_fields[f'eth_{layer_index}_dst'] = dst_mac_var

        # 类型
        ttk.Label(frame, text="类型:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        type_var = tk.StringVar(value=f"0x{eth_layer.type:04x}")
        ttk.Entry(frame, textvariable=type_var, width=10).grid(row=2, column=1, sticky=tk.W, padx=(0, 10), pady=(5, 0))
        self.edit_fields[f'eth_{layer_index}_type'] = type_var

    def create_ipv4_editor(self, parent, ip_layer, layer_index):
        """创建IPv4层编辑器"""
        frame = ttk.LabelFrame(parent, text="IPv4层", padding="10")
        frame.pack(fill=tk.X, padx=5, pady=5)
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)

        # 第一行：版本、头长度、服务类型、总长度
        ttk.Label(frame, text="版本:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        version_var = tk.StringVar(value=str(ip_layer.version))
        ttk.Entry(frame, textvariable=version_var, width=5).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        self.edit_fields[f'ip_{layer_index}_version'] = version_var

        ttk.Label(frame, text="头长度:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        ihl_var = tk.StringVar(value=str(ip_layer.ihl))
        ttk.Entry(frame, textvariable=ihl_var, width=5).grid(row=0, column=3, sticky=tk.W)
        self.edit_fields[f'ip_{layer_index}_ihl'] = ihl_var

        # 第二行：服务类型、总长度
        ttk.Label(frame, text="服务类型:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        tos_var = tk.StringVar(value=str(ip_layer.tos))
        ttk.Entry(frame, textvariable=tos_var, width=5).grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        self.edit_fields[f'ip_{layer_index}_tos'] = tos_var

        ttk.Label(frame, text="总长度:").grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        len_var = tk.StringVar(value=str(ip_layer.len))
        ttk.Entry(frame, textvariable=len_var, width=8).grid(row=1, column=3, sticky=tk.W, pady=(5, 0))
        self.edit_fields[f'ip_{layer_index}_len'] = len_var

        # 第三行：标识、标志、片偏移
        ttk.Label(frame, text="标识:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        id_var = tk.StringVar(value=str(ip_layer.id))
        ttk.Entry(frame, textvariable=id_var, width=8).grid(row=2, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        self.edit_fields[f'ip_{layer_index}_id'] = id_var

        ttk.Label(frame, text="标志:").grid(row=2, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        flags_var = tk.StringVar(value=str(ip_layer.flags))
        ttk.Entry(frame, textvariable=flags_var, width=5).grid(row=2, column=3, sticky=tk.W, pady=(5, 0))
        self.edit_fields[f'ip_{layer_index}_flags'] = flags_var

        # 第四行：TTL、协议
        ttk.Label(frame, text="TTL:").grid(row=3, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        ttl_var = tk.StringVar(value=str(ip_layer.ttl))
        ttk.Entry(frame, textvariable=ttl_var, width=5).grid(row=3, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        self.edit_fields[f'ip_{layer_index}_ttl'] = ttl_var

        ttk.Label(frame, text="协议:").grid(row=3, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        proto_var = tk.StringVar(value=str(ip_layer.proto))
        ttk.Entry(frame, textvariable=proto_var, width=5).grid(row=3, column=3, sticky=tk.W, pady=(5, 0))
        self.edit_fields[f'ip_{layer_index}_proto'] = proto_var

        # 第五行：源IP地址
        ttk.Label(frame, text="源IP地址:").grid(row=4, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        src_var = tk.StringVar(value=str(ip_layer.src))
        ttk.Entry(frame, textvariable=src_var, width=20).grid(row=4, column=1, columnspan=3, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        self.edit_fields[f'ip_{layer_index}_src'] = src_var

        # 第六行：目标IP地址
        ttk.Label(frame, text="目标IP地址:").grid(row=5, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        dst_var = tk.StringVar(value=str(ip_layer.dst))
        ttk.Entry(frame, textvariable=dst_var, width=20).grid(row=5, column=1, columnspan=3, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        self.edit_fields[f'ip_{layer_index}_dst'] = dst_var

    def create_ipv6_editor(self, parent, ipv6_layer, layer_index):
        """创建IPv6层编辑器"""
        frame = ttk.LabelFrame(parent, text="IPv6层", padding="10")
        frame.pack(fill=tk.X, padx=5, pady=5)
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)

        # 版本、流量类别、流标签
        ttk.Label(frame, text="版本:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        version_var = tk.StringVar(value=str(ipv6_layer.version))
        ttk.Entry(frame, textvariable=version_var, width=5).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        self.edit_fields[f'ipv6_{layer_index}_version'] = version_var

        ttk.Label(frame, text="流量类别:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        tc_var = tk.StringVar(value=str(ipv6_layer.tc))
        ttk.Entry(frame, textvariable=tc_var, width=5).grid(row=0, column=3, sticky=tk.W)
        self.edit_fields[f'ipv6_{layer_index}_tc'] = tc_var

        # 载荷长度、下一个头部、跳数限制
        ttk.Label(frame, text="载荷长度:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        plen_var = tk.StringVar(value=str(ipv6_layer.plen))
        ttk.Entry(frame, textvariable=plen_var, width=8).grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        self.edit_fields[f'ipv6_{layer_index}_plen'] = plen_var

        ttk.Label(frame, text="跳数限制:").grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        hlim_var = tk.StringVar(value=str(ipv6_layer.hlim))
        ttk.Entry(frame, textvariable=hlim_var, width=5).grid(row=1, column=3, sticky=tk.W, pady=(5, 0))
        self.edit_fields[f'ipv6_{layer_index}_hlim'] = hlim_var

        # 源IPv6地址
        ttk.Label(frame, text="源IPv6地址:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        src_var = tk.StringVar(value=str(ipv6_layer.src))
        ttk.Entry(frame, textvariable=src_var, width=40).grid(row=2, column=1, columnspan=3, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        self.edit_fields[f'ipv6_{layer_index}_src'] = src_var

        # 目标IPv6地址
        ttk.Label(frame, text="目标IPv6地址:").grid(row=3, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        dst_var = tk.StringVar(value=str(ipv6_layer.dst))
        ttk.Entry(frame, textvariable=dst_var, width=40).grid(row=3, column=1, columnspan=3, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        self.edit_fields[f'ipv6_{layer_index}_dst'] = dst_var

    def create_tcp_editor(self, parent, tcp_layer, layer_index):
        """创建TCP层编辑器"""
        frame = ttk.LabelFrame(parent, text="TCP层", padding="10")
        frame.pack(fill=tk.X, padx=5, pady=5)
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)

        # 源端口、目标端口
        ttk.Label(frame, text="源端口:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        sport_var = tk.StringVar(value=str(tcp_layer.sport))
        ttk.Entry(frame, textvariable=sport_var, width=8).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        self.edit_fields[f'tcp_{layer_index}_sport'] = sport_var

        ttk.Label(frame, text="目标端口:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        dport_var = tk.StringVar(value=str(tcp_layer.dport))
        ttk.Entry(frame, textvariable=dport_var, width=8).grid(row=0, column=3, sticky=tk.W)
        self.edit_fields[f'tcp_{layer_index}_dport'] = dport_var

        # 序列号
        ttk.Label(frame, text="序列号:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        seq_var = tk.StringVar(value=str(tcp_layer.seq))
        ttk.Entry(frame, textvariable=seq_var, width=15).grid(row=1, column=1, columnspan=3, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        self.edit_fields[f'tcp_{layer_index}_seq'] = seq_var

        # 确认号
        ttk.Label(frame, text="确认号:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        ack_var = tk.StringVar(value=str(tcp_layer.ack))
        ttk.Entry(frame, textvariable=ack_var, width=15).grid(row=2, column=1, columnspan=3, sticky=(tk.W, tk.E), padx=(0, 10), pady=(5, 0))
        self.edit_fields[f'tcp_{layer_index}_ack'] = ack_var

        # 窗口大小、紧急指针
        ttk.Label(frame, text="窗口大小:").grid(row=3, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        window_var = tk.StringVar(value=str(tcp_layer.window))
        ttk.Entry(frame, textvariable=window_var, width=8).grid(row=3, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        self.edit_fields[f'tcp_{layer_index}_window'] = window_var

        ttk.Label(frame, text="紧急指针:").grid(row=3, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        urgptr_var = tk.StringVar(value=str(tcp_layer.urgptr))
        ttk.Entry(frame, textvariable=urgptr_var, width=8).grid(row=3, column=3, sticky=tk.W, pady=(5, 0))
        self.edit_fields[f'tcp_{layer_index}_urgptr'] = urgptr_var

        # TCP标志位
        flags_frame = ttk.LabelFrame(frame, text="TCP标志位", padding="5")
        flags_frame.grid(row=4, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=(10, 0))

        # 创建标志位复选框
        self.tcp_flags = {}
        flag_names = [('FIN', 0x01), ('SYN', 0x02), ('RST', 0x04), ('PSH', 0x08), ('ACK', 0x10), ('URG', 0x20)]

        for i, (flag_name, flag_value) in enumerate(flag_names):
            var = tk.BooleanVar(value=bool(tcp_layer.flags & flag_value))
            ttk.Checkbutton(flags_frame, text=flag_name, variable=var).grid(row=0, column=i, padx=10, sticky=tk.W)
            self.tcp_flags[f'tcp_{layer_index}_{flag_name.lower()}'] = var

    def create_udp_editor(self, parent, udp_layer, layer_index):
        """创建UDP层编辑器"""
        frame = ttk.LabelFrame(parent, text="UDP层", padding="10")
        frame.pack(fill=tk.X, padx=5, pady=5)
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)

        # 源端口、目标端口
        ttk.Label(frame, text="源端口:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        sport_var = tk.StringVar(value=str(udp_layer.sport))
        ttk.Entry(frame, textvariable=sport_var, width=8).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        self.edit_fields[f'udp_{layer_index}_sport'] = sport_var

        ttk.Label(frame, text="目标端口:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        dport_var = tk.StringVar(value=str(udp_layer.dport))
        ttk.Entry(frame, textvariable=dport_var, width=8).grid(row=0, column=3, sticky=tk.W)
        self.edit_fields[f'udp_{layer_index}_dport'] = dport_var

        # 长度、校验和
        ttk.Label(frame, text="长度:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        len_var = tk.StringVar(value=str(udp_layer.len))
        ttk.Entry(frame, textvariable=len_var, width=8).grid(row=1, column=1, sticky=tk.W, padx=(0, 20), pady=(5, 0))
        self.edit_fields[f'udp_{layer_index}_len'] = len_var

        ttk.Label(frame, text="校验和:").grid(row=1, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        chksum_var = tk.StringVar(value=str(udp_layer.chksum))
        ttk.Entry(frame, textvariable=chksum_var, width=8).grid(row=1, column=3, sticky=tk.W, pady=(5, 0))
        self.edit_fields[f'udp_{layer_index}_chksum'] = chksum_var

    def create_payload_editor(self, parent, payload_data, layer_index):
        """创建应用层数据编辑器"""
        frame = ttk.LabelFrame(parent, text="应用层数据 (Payload)", padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        # 数据格式选择
        format_frame = ttk.Frame(frame)
        format_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(format_frame, text="数据格式:").pack(side=tk.LEFT, padx=(0, 10))

        format_var = tk.StringVar(value="十六进制")
        format_combo = ttk.Combobox(format_frame, textvariable=format_var,
                                   values=["十六进制", "ASCII", "UTF-8"],
                                   state="readonly", width=10)
        format_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.edit_fields[f'payload_{layer_index}_format'] = format_var

        # 数据长度显示
        length_label = ttk.Label(format_frame, text=f"长度: {len(payload_data)} 字节")
        length_label.pack(side=tk.LEFT, padx=(10, 0))

        # 数据编辑区域
        text_frame = ttk.Frame(frame)
        text_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)

        # 文本编辑器
        text_widget = tk.Text(text_frame, wrap=tk.WORD, height=10, font=("Consolas", 10))
        text_scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=text_scrollbar.set)

        text_widget.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        text_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # 初始化数据显示
        self.update_payload_display(text_widget, payload_data, "十六进制")
        self.edit_fields[f'payload_{layer_index}_text'] = text_widget
        self.edit_fields[f'payload_{layer_index}_original'] = payload_data

        # 绑定格式切换事件
        def on_format_change(event):
            # 获取当前格式（切换前的格式）
            old_format = getattr(on_format_change, 'last_format', "十六进制")
            # 从当前显示获取数据
            current_data = self.get_payload_from_text(text_widget, old_format)
            # 获取新格式
            new_format = format_var.get()
            # 更新显示
            self.update_payload_display(text_widget, current_data, new_format)
            # 记录当前格式，供下次切换使用
            on_format_change.last_format = new_format

        # 初始化格式记录
        on_format_change.last_format = "十六进制"

        format_combo.bind('<<ComboboxSelected>>', on_format_change)

    def create_trailer_editor(self, parent, trailer_info, layer_index):
        """创建Trailer编辑器"""
        # 根据是否有trailer显示不同的标题
        if trailer_info['type'] == 'none':
            title = "数据包尾部 (Trailer) - 点击添加尾部数据"
        else:
            title = f"数据包尾部 (Trailer) - {trailer_info['description']}"

        frame = ttk.LabelFrame(parent, text=title, padding="10")
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(2, weight=1)

        # Trailer类型显示
        type_frame = ttk.Frame(frame)
        type_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(type_frame, text="类型:").pack(side=tk.LEFT, padx=(0, 10))

        trailer_type_var = tk.StringVar(value=trailer_info['type'])
        type_combo = ttk.Combobox(type_frame, textvariable=trailer_type_var,
                                 values=["none", "padding", "custom", "fcs", "vlan_tag"],
                                 state="readonly", width=12)
        type_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.edit_fields[f'trailer_{layer_index}_type'] = trailer_type_var

        # 类型描述标签
        type_desc_var = tk.StringVar()
        type_desc_label = ttk.Label(type_frame, textvariable=type_desc_var, foreground="gray")
        type_desc_label.pack(side=tk.LEFT, padx=(10, 0))

        # 数据格式选择
        format_frame = ttk.Frame(frame)
        format_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(format_frame, text="数据格式:").pack(side=tk.LEFT, padx=(0, 10))

        format_var = tk.StringVar(value="十六进制")
        format_combo = ttk.Combobox(format_frame, textvariable=format_var,
                                   values=["十六进制", "ASCII", "UTF-8"],
                                   state="readonly", width=10)
        format_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.edit_fields[f'trailer_{layer_index}_format'] = format_var

        # 数据长度显示
        trailer_data = trailer_info['data']
        length_label = ttk.Label(format_frame, text=f"长度: {len(trailer_data)} 字节")
        length_label.pack(side=tk.LEFT, padx=(10, 0))

        # 数据编辑区域
        text_frame = ttk.Frame(frame)
        text_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)

        # 文本编辑器
        text_widget = tk.Text(text_frame, wrap=tk.WORD, height=8, font=("Consolas", 10))

        # 操作按钮（移到文本编辑器创建之后）
        button_frame = ttk.Frame(format_frame)
        button_frame.pack(side=tk.RIGHT)

        # 清空trailer按钮
        clear_btn = ttk.Button(button_frame, text="清空", width=8,
                              command=lambda: self.clear_trailer_data(text_widget))
        clear_btn.pack(side=tk.LEFT, padx=(5, 0))

        # 生成padding按钮
        padding_btn = ttk.Button(button_frame, text="生成填充", width=10,
                                command=lambda: self.generate_padding_data(text_widget, format_var))
        padding_btn.pack(side=tk.LEFT, padx=(5, 0))
        text_scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=text_scrollbar.set)

        text_widget.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        text_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))

        # 初始化数据显示
        self.update_payload_display(text_widget, trailer_data, "十六进制")
        self.edit_fields[f'trailer_{layer_index}_text'] = text_widget
        self.edit_fields[f'trailer_{layer_index}_original'] = trailer_data

        # 绑定格式切换事件
        def on_format_change(event):
            # 获取当前格式（切换前的格式）
            old_format = getattr(on_format_change, 'last_format', "十六进制")
            # 从当前显示获取数据
            current_data = self.get_payload_from_text(text_widget, old_format)
            # 获取新格式
            new_format = format_var.get()
            # 更新显示
            self.update_payload_display(text_widget, current_data, new_format)
            # 记录当前格式，供下次切换使用
            on_format_change.last_format = new_format

        # 初始化格式记录
        on_format_change.last_format = "十六进制"

        format_combo.bind('<<ComboboxSelected>>', on_format_change)

        # 绑定类型切换事件
        def on_type_change(event):
            trailer_type = trailer_type_var.get()
            if trailer_type == "none":
                type_desc_var.set("无尾部数据")
                text_widget.delete(1.0, tk.END)
            elif trailer_type == "padding":
                type_desc_var.set("以太网填充数据")
                # 如果当前没有数据，提供默认的4字节padding
                if not text_widget.get(1.0, tk.END).strip():
                    padding_data = b'\x00' * 4
                    self.update_payload_display(text_widget, padding_data, format_var.get())
            elif trailer_type == "custom":
                type_desc_var.set("自定义尾部数据")
            elif trailer_type == "fcs":
                type_desc_var.set("帧校验序列")
                # 如果当前没有数据，提供默认的4字节FCS
                if not text_widget.get(1.0, tk.END).strip():
                    fcs_data = b'\x00\x00\x00\x00'
                    self.update_payload_display(text_widget, fcs_data, format_var.get())
            elif trailer_type == "vlan_tag":
                type_desc_var.set("VLAN标签")
                # 如果当前没有数据，提供默认的4字节VLAN标签
                if not text_widget.get(1.0, tk.END).strip():
                    vlan_data = b'\x81\x00\x00\x64'  # VLAN ID 100
                    self.update_payload_display(text_widget, vlan_data, format_var.get())

        # 初始化类型描述
        on_type_change(None)

        type_combo.bind('<<ComboboxSelected>>', on_type_change)

    def clear_trailer_data(self, text_widget):
        """清空trailer数据"""
        text_widget.delete(1.0, tk.END)

    def generate_padding_data(self, text_widget, format_var):
        """生成填充数据"""
        # 弹出对话框询问填充长度
        from tkinter import simpledialog

        length = simpledialog.askinteger("生成填充数据", "请输入填充长度（字节）:",
                                       minvalue=1, maxvalue=1500, initialvalue=4)
        if length:
            padding_data = b'\x00' * length
            format_type = format_var.get()
            self.update_payload_display(text_widget, padding_data, format_type)

    def get_payload_data(self, packet):
        """获取数据包的应用层数据"""
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Ether

        # 逐层剥离，找到最内层的数据
        current = packet
        while current:
            if hasattr(current, 'payload') and current.payload:
                if isinstance(current.payload, (bytes, str)):
                    return current.payload if isinstance(current.payload, bytes) else current.payload.encode()
                elif hasattr(current.payload, '__class__') and current.payload.__class__.__name__ == 'Raw':
                    return bytes(current.payload)
                else:
                    current = current.payload
            else:
                break

        return b''

    def detect_packet_trailer(self, packet):
        """检测数据包中的trailer数据"""
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.l2 import Ether

            # 获取数据包的原始字节
            packet_bytes = bytes(packet)

            # 计算预期的数据包长度
            expected_length = 0
            trailer_data = b''

            # 以太网帧分析
            if Ether in packet:
                eth_header_len = 14  # 以太网头部长度
                expected_length += eth_header_len

                # IP层分析
                if IP in packet:
                    ip_layer = packet[IP]
                    ip_total_len = ip_layer.len if hasattr(ip_layer, 'len') and ip_layer.len else len(bytes(ip_layer))
                    expected_length += ip_total_len
                elif IPv6 in packet:
                    ipv6_layer = packet[IPv6]
                    ipv6_header_len = 40
                    ipv6_payload_len = ipv6_layer.plen if hasattr(ipv6_layer, 'plen') and ipv6_layer.plen else 0
                    expected_length += ipv6_header_len + ipv6_payload_len

                # 检查是否有trailer
                if len(packet_bytes) > expected_length:
                    trailer_data = packet_bytes[expected_length:]

                    # 检查是否是以太网padding（通常是0x00填充）
                    if len(trailer_data) > 0:
                        # 如果trailer全是0x00，可能是padding
                        if all(b == 0 for b in trailer_data):
                            return {'type': 'padding', 'data': trailer_data, 'description': f'以太网填充 ({len(trailer_data)} 字节)'}
                        else:
                            return {'type': 'custom', 'data': trailer_data, 'description': f'自定义尾部数据 ({len(trailer_data)} 字节)'}

            return None

        except Exception as e:
            print(f"检测trailer时发生错误: {e}")
            return None

    def update_payload_display(self, text_widget, data, format_type):
        """更新应用层数据显示"""
        text_widget.config(state=tk.NORMAL)
        text_widget.delete(1.0, tk.END)

        if not data:
            text_widget.insert(tk.END, "")
            text_widget.config(state=tk.NORMAL)
            return

        try:
            if format_type == "十六进制":
                hex_str = data.hex().upper()
                # 格式化为每行16字节，每2字节一个空格
                formatted = ""
                for i in range(0, len(hex_str), 32):  # 32个字符 = 16字节
                    line = hex_str[i:i+32]
                    formatted_line = " ".join([line[j:j+2] for j in range(0, len(line), 2)])
                    formatted += formatted_line
                    if i + 32 < len(hex_str):  # 不是最后一行
                        formatted += "\n"
                text_widget.insert(tk.END, formatted)

            elif format_type == "ASCII":
                ascii_str = ""
                for byte in data:
                    if 32 <= byte <= 126:  # 可打印ASCII字符
                        ascii_str += chr(byte)
                    else:
                        ascii_str += f"\\x{byte:02X}"
                text_widget.insert(tk.END, ascii_str)

            elif format_type == "UTF-8":
                utf8_str = data.decode('utf-8', errors='replace')
                text_widget.insert(tk.END, utf8_str)

        except Exception as e:
            error_msg = f"显示错误 ({format_type}): {str(e)}"
            text_widget.insert(tk.END, error_msg)
            print(f"显示数据错误: {e}, 数据长度: {len(data)}, 格式: {format_type}")

        text_widget.config(state=tk.NORMAL)  # 保持可编辑

    def get_payload_from_text(self, text_widget, format_type):
        """从文本编辑器获取应用层数据"""
        content = text_widget.get(1.0, tk.END).strip()

        if not content:
            return b''

        if format_type == "十六进制":
            try:
                # 移除空格、换行符和其他分隔符
                hex_str = content.replace(" ", "").replace("\n", "").replace("\r", "").replace(":", "").replace("-", "")
                # 确保是偶数长度
                if len(hex_str) % 2 != 0:
                    hex_str = "0" + hex_str
                return bytes.fromhex(hex_str)
            except ValueError as e:
                print(f"十六进制解析错误: {e}, 内容: {repr(content)}")
                return b''

        elif format_type == "ASCII":
            # 处理转义序列
            result = b''
            i = 0
            while i < len(content):
                if i + 3 < len(content) and content[i:i+2] == '\\x':
                    try:
                        byte_val = int(content[i+2:i+4], 16)
                        result += bytes([byte_val])
                        i += 4
                    except ValueError:
                        result += content[i].encode('ascii', errors='ignore')
                        i += 1
                else:
                    result += content[i].encode('ascii', errors='ignore')
                    i += 1
            return result

        elif format_type == "UTF-8":
            try:
                return content.encode('utf-8', errors='replace')
            except Exception as e:
                print(f"UTF-8编码错误: {e}")
                return content.encode('utf-8', errors='ignore')

        return b''

    def apply_packet_changes(self, editor_frame):
        """应用数据包修改"""
        try:
            packet_index = self.current_packet_index.get()
            if packet_index >= len(self.packet_generator.packets):
                messagebox.showerror("错误", "无效的数据包索引")
                return

            # 清除之前的错误信息
            self.last_rebuild_error = None

            # 重构数据包
            new_packet = self.rebuild_packet(packet_index)

            if new_packet:
                # 更新数据包
                self.packet_generator.packets[packet_index] = new_packet

                # 更新主预览列表
                self.update_packet_preview()

                # 重新加载编辑器以显示更新后的数据
                self.load_packet_for_editing(editor_frame, packet_index)

                messagebox.showinfo("成功", "数据包修改已应用，编辑器已更新")
            else:
                # 显示详细的错误信息
                error_msg = "重构数据包失败"
                if hasattr(self, 'last_rebuild_error') and self.last_rebuild_error:
                    error_msg += f"\n\n详细错误信息：\n{self.last_rebuild_error}"
                messagebox.showerror("错误", error_msg)

        except Exception as e:
            messagebox.showerror("错误", f"应用修改时发生错误：{str(e)}")

    def rebuild_packet(self, packet_index):
        """重构数据包"""
        try:
            from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw

            original_packet = self.packet_generator.packets[packet_index]
            layers = []

            # 重构以太网层
            if Ether in original_packet:
                eth_fields = {}
                for key, var in self.edit_fields.items():
                    if key.startswith('eth_0_'):
                        field_name = key.split('_')[-1]
                        if field_name == 'type':
                            value = var.get()
                            if value and value != 'None':
                                eth_fields[field_name] = int(value, 16)
                        else:
                            value = var.get()
                            if value and value != 'None':
                                eth_fields[field_name] = value

                layers.append(Ether(**eth_fields))

            # 重构IP层
            if IP in original_packet:
                ip_fields = {}
                for key, var in self.edit_fields.items():
                    if key.startswith('ip_1_'):
                        field_name = key.split('_')[-1]
                        if field_name in ['version', 'ihl', 'tos', 'len', 'id', 'flags', 'ttl', 'proto']:
                            value = var.get()
                            if value and value != 'None':
                                try:
                                    ip_fields[field_name] = int(value)
                                except ValueError:
                                    print(f"警告: IP字段 {field_name} 的值 '{value}' 无法转换为整数，跳过")
                        else:
                            value = var.get()
                            if value and value != 'None':
                                ip_fields[field_name] = value

                layers.append(IP(**ip_fields))

            elif IPv6 in original_packet:
                ipv6_fields = {}
                for key, var in self.edit_fields.items():
                    if key.startswith('ipv6_1_'):
                        field_name = key.split('_')[-1]
                        if field_name in ['version', 'tc', 'plen', 'hlim']:
                            value = var.get()
                            if value and value != 'None':
                                try:
                                    ipv6_fields[field_name] = int(value)
                                except ValueError:
                                    print(f"警告: IPv6字段 {field_name} 的值 '{value}' 无法转换为整数，跳过")
                        else:
                            value = var.get()
                            if value and value != 'None':
                                ipv6_fields[field_name] = value

                layers.append(IPv6(**ipv6_fields))

            # 重构传输层
            if TCP in original_packet:
                tcp_fields = {}
                for key, var in self.edit_fields.items():
                    if key.startswith('tcp_2_'):
                        field_name = key.split('_')[-1]
                        if field_name in ['sport', 'dport', 'seq', 'ack', 'window', 'urgptr']:
                            value = var.get()
                            if value and value != 'None':
                                try:
                                    tcp_fields[field_name] = int(value)
                                except ValueError:
                                    print(f"警告: TCP字段 {field_name} 的值 '{value}' 无法转换为整数，跳过")

                # 处理TCP标志位
                flags = 0
                flag_mapping = {'fin': 0x01, 'syn': 0x02, 'rst': 0x04, 'psh': 0x08, 'ack': 0x10, 'urg': 0x20}
                for flag_name, flag_value in flag_mapping.items():
                    if f'tcp_2_{flag_name}' in self.tcp_flags and self.tcp_flags[f'tcp_2_{flag_name}'].get():
                        flags |= flag_value

                tcp_fields['flags'] = flags
                layers.append(TCP(**tcp_fields))

            elif UDP in original_packet:
                udp_fields = {}
                for key, var in self.edit_fields.items():
                    if key.startswith('udp_2_'):
                        field_name = key.split('_')[-1]
                        if field_name in ['sport', 'dport', 'len', 'chksum']:
                            value = var.get()
                            if value and value != 'None':
                                try:
                                    udp_fields[field_name] = int(value)
                                except ValueError:
                                    print(f"警告: UDP字段 {field_name} 的值 '{value}' 无法转换为整数，跳过")

                layers.append(UDP(**udp_fields))

            # 重构应用层数据
            payload_text_key = None
            payload_format_key = None
            trailer_text_key = None
            trailer_format_key = None

            for key in self.edit_fields.keys():
                if key.endswith('_text'):
                    if 'payload' in key:
                        payload_text_key = key
                    elif 'trailer' in key:
                        trailer_text_key = key
                elif key.endswith('_format'):
                    if 'payload' in key:
                        payload_format_key = key
                    elif 'trailer' in key:
                        trailer_format_key = key

            if payload_text_key and payload_format_key:
                text_widget = self.edit_fields[payload_text_key]
                format_var = self.edit_fields[payload_format_key]
                payload_data = self.get_payload_from_text(text_widget, format_var.get())

                if payload_data:
                    layers.append(Raw(load=payload_data))

            # 组合所有层
            if layers:
                packet = layers[0]
                for layer in layers[1:]:
                    packet = packet / layer

                # 重新计算长度字段和校验和
                packet = self.recalculate_packet_fields(packet)

                # 添加trailer数据
                if trailer_text_key and trailer_format_key:
                    text_widget = self.edit_fields[trailer_text_key]
                    format_var = self.edit_fields[trailer_format_key]
                    trailer_data = self.get_payload_from_text(text_widget, format_var.get())

                    if trailer_data:
                        # 将trailer数据附加到数据包末尾
                        packet_bytes = bytes(packet)
                        packet_with_trailer = packet_bytes + trailer_data

                        # 重新构建数据包（保持原有结构但包含trailer）
                        try:
                            # 使用原始数据包类型重新构建
                            packet = packet.__class__(packet_with_trailer)
                        except:
                            # 如果重构失败，使用Raw层包装
                            from scapy.all import Raw
                            packet = Raw(packet_with_trailer)

                return packet

            return None

        except Exception as e:
            print(f"重构数据包错误: {e}")
            import traceback
            traceback.print_exc()
            # 将错误信息存储，供apply_packet_changes使用
            self.last_rebuild_error = str(e)
            return None

    def recalculate_packet_fields(self, packet):
        """重新计算数据包的长度字段和校验和"""
        try:
            from scapy.all import IP, IPv6, TCP, UDP, Raw

            print(f"🔧 开始重新计算数据包字段...")

            # 获取载荷大小
            payload_size = 0
            if Raw in packet:
                payload_size = len(packet[Raw].load)
                print(f"📦 应用层数据大小: {payload_size} 字节")

            # 重新计算UDP长度
            if UDP in packet:
                udp_layer = packet[UDP]
                # UDP长度 = UDP头部(8字节) + 数据长度
                new_udp_length = 8 + payload_size
                print(f"🔄 重新计算UDP长度: {udp_layer.len} → {new_udp_length}")
                udp_layer.len = new_udp_length

                # 删除UDP校验和，让Scapy重新计算
                if hasattr(udp_layer, 'chksum'):
                    del udp_layer.chksum
                    print(f"🔄 删除UDP校验和，将重新计算")

            # 重新计算IP长度
            if IP in packet:
                ip_layer = packet[IP]
                # 计算IP层以下所有数据的总长度
                transport_and_payload_size = 0

                if UDP in packet:
                    transport_and_payload_size = 8 + payload_size  # UDP头部 + 数据
                elif TCP in packet:
                    # TCP头部通常是20字节（不考虑选项）
                    transport_and_payload_size = 20 + payload_size

                # IP总长度 = IP头部(20字节) + 传输层头部 + 数据
                new_ip_length = 20 + transport_and_payload_size
                print(f"🔄 重新计算IPv4长度: {ip_layer.len} → {new_ip_length}")
                ip_layer.len = new_ip_length

                # 删除IP校验和，让Scapy重新计算
                if hasattr(ip_layer, 'chksum'):
                    del ip_layer.chksum
                    print(f"🔄 删除IPv4校验和，将重新计算")

            elif IPv6 in packet:
                ipv6_layer = packet[IPv6]
                # 计算IPv6载荷长度（不包括IPv6头部的40字节）
                transport_and_payload_size = 0

                if UDP in packet:
                    transport_and_payload_size = 8 + payload_size  # UDP头部 + 数据
                elif TCP in packet:
                    transport_and_payload_size = 20 + payload_size  # TCP头部 + 数据

                print(f"🔄 重新计算IPv6载荷长度: {ipv6_layer.plen} → {transport_and_payload_size}")
                ipv6_layer.plen = transport_and_payload_size

            # 删除传输层校验和，让Scapy重新计算
            if TCP in packet:
                tcp_layer = packet[TCP]
                if hasattr(tcp_layer, 'chksum'):
                    del tcp_layer.chksum
                    print(f"🔄 删除TCP校验和，将重新计算")

            # 重新构建数据包以触发校验和计算
            print(f"🔄 重新构建数据包以触发校验和计算...")
            rebuilt_packet = packet.__class__(bytes(packet))

            print(f"✅ 数据包字段重新计算完成")
            return rebuilt_packet

        except Exception as e:
            print(f"❌ 重新计算数据包字段时发生错误: {e}")
            return packet  # 返回原始数据包

    def simple_ip_conversion_dialog(self, parent_window):
        """简单IP转换对话框"""
        dialog = tk.Toplevel(parent_window)
        dialog.title("IPv4 → IPv6 转换工具")

        # 获取屏幕尺寸
        screen_width = dialog.winfo_screenwidth()
        screen_height = dialog.winfo_screenheight()

        # 设置对话框尺寸（适应不同分辨率）
        dialog_width = min(600, int(screen_width * 0.4))
        dialog_height = min(500, int(screen_height * 0.6))

        # 计算居中位置
        x = (screen_width - dialog_width) // 2
        y = (screen_height - dialog_height) // 2

        dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
        dialog.resizable(True, True)  # 允许调整大小
        dialog.minsize(500, 400)  # 设置最小尺寸
        dialog.transient(parent_window)
        dialog.grab_set()

        # 创建主框架
        main_frame = ttk.Frame(dialog, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 标题和说明
        title_label = ttk.Label(main_frame, text="🔄 IPv4 到 IPv6 转换", font=("Arial", 12, "bold"))
        title_label.pack(pady=(0, 8))

        info_label = ttk.Label(main_frame, text="将所有IPv4数据包转换为IPv6格式", font=("Arial", 9))
        info_label.pack(pady=(0, 15))

        # IPv6地址设置
        addr_frame = ttk.LabelFrame(main_frame, text="IPv6地址设置", padding="8")
        addr_frame.pack(fill=tk.X, pady=(0, 15))

        # 配置网格权重
        addr_frame.columnconfigure(1, weight=1)

        ttk.Label(addr_frame, text="源IPv6地址:").grid(row=0, column=0, sticky=tk.W, pady=3)
        src_ipv6_var = tk.StringVar(value="2001:db8::1")
        src_entry = ttk.Entry(addr_frame, textvariable=src_ipv6_var)
        src_entry.grid(row=0, column=1, sticky=tk.EW, padx=(8, 0), pady=3)

        ttk.Label(addr_frame, text="目标IPv6地址:").grid(row=1, column=0, sticky=tk.W, pady=3)
        dst_ipv6_var = tk.StringVar(value="2001:db8::2")
        dst_entry = ttk.Entry(addr_frame, textvariable=dst_ipv6_var)
        dst_entry.grid(row=1, column=1, sticky=tk.EW, padx=(8, 0), pady=3)

        # 状态显示
        status_frame = ttk.LabelFrame(main_frame, text="转换状态", padding="8")
        status_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        # 创建文本框和滚动条的容器
        text_container = ttk.Frame(status_frame)
        text_container.pack(fill=tk.BOTH, expand=True)

        status_text = tk.Text(text_container, height=8, wrap=tk.WORD, font=("Consolas", 9))
        status_scrollbar = ttk.Scrollbar(text_container, orient=tk.VERTICAL, command=status_text.yview)
        status_text.configure(yscrollcommand=status_scrollbar.set)

        status_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        status_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def update_status(message):
            status_text.insert(tk.END, message + "\n")
            status_text.see(tk.END)
            status_text.update()

        def simple_convert():
            """执行简单的IPv4到IPv6转换"""
            try:
                update_status("开始转换...")

                if not self.packet_generator.packets:
                    update_status("错误：没有数据包可转换")
                    return

                src_ip = src_ipv6_var.get().strip()
                dst_ip = dst_ipv6_var.get().strip()

                if not src_ip or not dst_ip:
                    update_status("错误：请输入有效的IPv6地址")
                    return

                update_status(f"转换参数: {src_ip} → {dst_ip}")

                from scapy.layers.inet import IP
                from scapy.layers.inet6 import IPv6
                from scapy.layers.l2 import Ether

                converted_count = 0
                total_packets = len(self.packet_generator.packets)

                # 创建新的数据包列表
                new_packets = []

                for i, packet in enumerate(self.packet_generator.packets):
                    if IP in packet:
                        # 创建新的IPv6数据包
                        try:
                            # 获取原始信息
                            original_ip = packet[IP]

                            # 创建新的以太网层
                            if Ether in packet:
                                eth = packet[Ether]
                                new_eth = Ether(src=eth.src, dst=eth.dst, type=0x86DD)  # IPv6
                            else:
                                new_eth = None

                            # 创建IPv6层
                            new_ipv6 = IPv6(src=src_ip, dst=dst_ip, hlim=64)

                            # 复制传输层
                            if original_ip.payload:
                                new_ipv6.payload = original_ip.payload

                            # 构建新数据包
                            if new_eth:
                                new_packet = new_eth / new_ipv6
                            else:
                                new_packet = new_ipv6

                            new_packets.append(new_packet)
                            converted_count += 1

                            if (i + 1) % 100 == 0:
                                update_status(f"已转换 {i + 1}/{total_packets} 个数据包")

                        except Exception as e:
                            update_status(f"转换数据包 {i+1} 失败: {e}")
                            new_packets.append(packet)  # 保留原始数据包
                    else:
                        new_packets.append(packet)  # 非IPv4数据包保持不变

                # 替换数据包列表
                self.packet_generator.packets = new_packets

                update_status(f"转换完成！成功转换 {converted_count} 个数据包")

                # 验证结果
                ipv6_count = sum(1 for p in new_packets if IPv6 in p)
                ipv4_count = sum(1 for p in new_packets if IP in p)
                update_status(f"验证结果: {ipv6_count} IPv6, {ipv4_count} IPv4")

                # 更新界面
                self.update_packet_preview()
                if hasattr(self, 'refresh_editor_packet_list'):
                    self.refresh_editor_packet_list()

            except Exception as e:
                update_status(f"转换失败: {e}")

        def save_packets():
            """保存转换后的数据包"""
            try:
                filename = filedialog.asksaveasfilename(
                    title="保存转换后的PCAP文件",
                    defaultextension=".pcap",
                    filetypes=[("PCAP文件", "*.pcap"), ("所有文件", "*.*")]
                )

                if filename:
                    from scapy.utils import wrpcap
                    wrpcap(filename, self.packet_generator.packets)
                    update_status(f"已保存到: {filename}")
                    messagebox.showinfo("保存成功", f"已保存 {len(self.packet_generator.packets)} 个数据包")

            except Exception as e:
                update_status(f"保存失败: {e}")

        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(15, 0))

        # 使用网格布局确保按钮在不同分辨率下都能正常显示
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        button_frame.columnconfigure(2, weight=1)

        # 三个按钮平均分布
        convert_btn = ttk.Button(button_frame, text="✓ 确定转换", command=simple_convert)
        convert_btn.grid(row=0, column=0, sticky=tk.EW, padx=(0, 5))

        save_btn = ttk.Button(button_frame, text="💾 保存文件", command=save_packets)
        save_btn.grid(row=0, column=1, sticky=tk.EW, padx=5)

        close_btn = ttk.Button(button_frame, text="✕ 关闭", command=dialog.destroy)
        close_btn.grid(row=0, column=2, sticky=tk.EW, padx=(5, 0))

        # 添加初始状态提示
        update_status("准备就绪，请点击'确定转换'开始转换IPv4数据包为IPv6格式")


    def run(self):
        """运行GUI应用"""
        self.root.mainloop()
