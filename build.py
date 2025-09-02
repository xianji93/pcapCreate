#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PyInstaller打包脚本
用于创建Windows 7兼容的独立exe文件
"""

import os
import sys
import subprocess
import shutil

def build_exe():
    """构建exe文件"""
    print("开始构建PCAP生成工具...")
    
    # PyInstaller命令参数
    cmd = [
        'pyinstaller',
        '--onefile',                    # 打包成单个exe文件
        '--windowed',                   # 不显示控制台窗口
        '--name=PcapGenerator',         # 输出文件名
        '--icon=icon.ico',              # 图标文件（如果存在）
        '--add-data=gui;gui',           # 包含gui模块
        '--add-data=core;core',         # 包含core模块
        '--add-data=utils;utils',       # 包含utils模块
        '--hidden-import=scapy.all',    # 确保scapy被包含
        '--hidden-import=scapy.layers.inet',
        '--hidden-import=scapy.layers.inet6',
        '--hidden-import=scapy.layers.l2',
        '--clean',                      # 清理临时文件
        'main.py'                       # 主程序文件
    ]
    
    try:
        # 检查是否存在图标文件
        if not os.path.exists('icon.ico'):
            print("警告: 未找到icon.ico文件，将使用默认图标")
            cmd.remove('--icon=icon.ico')
        
        # 执行PyInstaller
        print("执行PyInstaller命令...")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        print("构建成功!")
        print(f"输出文件: dist/PcapGenerator.exe")
        
        # 清理临时文件
        if os.path.exists('build'):
            shutil.rmtree('build')
            print("已清理临时文件")
            
    except subprocess.CalledProcessError as e:
        print(f"构建失败: {e}")
        print(f"错误输出: {e.stderr}")
        return False
    except FileNotFoundError:
        print("错误: 未找到PyInstaller，请先安装: pip install pyinstaller")
        return False
        
    return True

def check_dependencies():
    """检查依赖项"""
    print("检查依赖项...")
    
    required_packages = ['scapy', 'pyinstaller']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✓ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"✗ {package}")
    
    if missing_packages:
        print(f"\n缺少以下依赖包: {', '.join(missing_packages)}")
        print("请运行: pip install -r requirements.txt")
        return False
        
    return True

if __name__ == "__main__":
    print("PCAP生成工具构建脚本")
    print("=" * 40)
    
    if not check_dependencies():
        sys.exit(1)
        
    if build_exe():
        print("\n构建完成! 可执行文件位于 dist/PcapGenerator.exe")
        print("该文件可以在Windows 7及更高版本上独立运行")
    else:
        print("\n构建失败!")
        sys.exit(1)
