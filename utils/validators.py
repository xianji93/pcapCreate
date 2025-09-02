#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
输入验证工具函数
"""

import re
import ipaddress

def validate_mac_address(mac):
    """
    验证MAC地址格式
    支持格式: XX:XX:XX:XX:XX:XX 或 XX-XX-XX-XX-XX-XX
    """
    if not mac:
        return False
    
    # 移除空格并转换为大写
    mac = mac.strip().upper()
    
    # 支持冒号和短横线分隔
    pattern = r'^([0-9A-F]{2}[:-]){5}[0-9A-F]{2}$'
    return bool(re.match(pattern, mac))

def validate_ipv4_address(ip):
    """验证IPv4地址格式"""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def validate_ipv6_address(ip):
    """验证IPv6地址格式"""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def validate_port(port):
    """验证端口号范围 (1-65535)"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def normalize_mac_address(mac):
    """
    标准化MAC地址格式为 XX:XX:XX:XX:XX:XX
    """
    if not validate_mac_address(mac):
        raise ValueError("无效的MAC地址格式")
    
    # 移除分隔符并转换为大写
    mac_clean = re.sub(r'[:-]', '', mac.strip().upper())
    
    # 重新格式化为冒号分隔
    return ':'.join([mac_clean[i:i+2] for i in range(0, 12, 2)])
