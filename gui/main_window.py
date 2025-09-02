#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主GUI窗口
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import sys

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.packet_generator import PacketGenerator
from utils.validators import validate_mac_address, validate_ipv4_address, validate_ipv6_address, validate_port, normalize_mac_address

class PcapGeneratorGUI:
    """PCAP生成器GUI主窗口"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PCAP生成工具 v1.0")
        self.root.geometry("600x700")
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
        
        ttk.Label(self.tcp_frame, text="数据大小(字节):").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.data_size_var = tk.StringVar(value="1460")
        self.data_size_entry = ttk.Entry(self.tcp_frame, textvariable=self.data_size_var, width=10)
        self.data_size_entry.grid(row=0, column=1, sticky=tk.W, padx=(0, 10))
        
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

            # 验证数据大小
            if self.protocol_var.get() == "TCP":
                try:
                    data_size = int(self.data_size_var.get())
                    if data_size < 0:
                        raise ValueError("数据大小不能为负数")
                except ValueError:
                    raise ValueError("数据大小必须是有效的数字")

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
                data_size = int(self.data_size_var.get())
                packets = self.packet_generator.generate_tcp_connection(
                    eth_frame, ip_layer, src_port, dst_port, data_size
                )
            else:  # UDP
                data_size = int(self.data_size_var.get()) if self.data_size_var.get() else 0
                packets = self.packet_generator.generate_udp_packets(
                    eth_frame, ip_layer, src_port, dst_port, data_size
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

    def run(self):
        """运行GUI应用"""
        self.root.mainloop()
