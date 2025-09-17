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

    # 清理之前的构建文件
    print("清理之前的构建文件...")
    for path in ['build', 'dist', 'PcapGenerator.spec']:
        if os.path.exists(path):
            if os.path.isdir(path):
                shutil.rmtree(path)
                print(f"已删除目录: {path}")
            else:
                os.remove(path)
                print(f"已删除文件: {path}")

    # PyInstaller命令参数
    cmd = [
        'pyinstaller',
        '--onefile',                    # 打包成单个exe文件
        '--windowed',                   # 不显示控制台窗口
        '--name=PcapGenerator',         # 输出文件名
        '--add-data=gui;gui',           # 包含gui模块
        '--add-data=core;core',         # 包含core模块
        '--add-data=utils;utils',       # 包含utils模块
        '--hidden-import=scapy',        # 确保scapy被包含
        '--hidden-import=scapy.all',
        '--hidden-import=scapy.layers',
        '--hidden-import=scapy.layers.inet',
        '--hidden-import=scapy.layers.inet6',
        '--hidden-import=scapy.layers.l2',
        '--hidden-import=scapy.packet',
        '--hidden-import=scapy.fields',
        '--hidden-import=scapy.base_classes',
        '--hidden-import=tkinter',
        '--hidden-import=tkinter.ttk',
        '--hidden-import=tkinter.messagebox',
        '--hidden-import=tkinter.filedialog',
        '--exclude-module=PyQt5',       # 排除PyQt5
        '--exclude-module=PyQt6',       # 排除PyQt6
        '--exclude-module=PySide2',     # 排除PySide2
        '--exclude-module=PySide6',     # 排除PySide6
        '--exclude-module=matplotlib.backends.qt_compat',  # 排除Qt相关后端
        '--clean',                      # 清理临时文件
        'main.py'                       # 主程序文件
    ]

    try:
        # 检查是否存在图标文件
        if os.path.exists('icon.ico'):
            cmd.insert(-2, '--icon=icon.ico')  # 在main.py之前插入
            print("使用图标文件: icon.ico")
        else:
            print("警告: 未找到icon.ico文件，将使用默认图标")

        # 执行PyInstaller
        print("执行PyInstaller命令...")
        print("命令:", ' '.join(cmd))

        # 不捕获输出，让错误信息直接显示
        result = subprocess.run(cmd, check=True)

        print("构建成功!")
        print(f"输出文件: dist/PcapGenerator.exe")

    except subprocess.CalledProcessError as e:
        print(f"构建失败，退出代码: {e.returncode}")
        print("请检查上面的错误信息")
        return False
    except FileNotFoundError:
        print("错误: 未找到PyInstaller，请先安装: pip install pyinstaller")
        return False

    return True

def check_dependencies():
    """检查依赖项"""
    print("检查依赖项...")

    missing_packages = []

    # 检查scapy模块
    try:
        __import__('scapy')
        print("✓ scapy")
    except ImportError:
        missing_packages.append('scapy')
        print("✗ scapy")

    # 检查pyinstaller命令
    try:
        result = subprocess.run(['pyinstaller', '--version'],
                              capture_output=True, text=True, check=True)
        print("✓ pyinstaller")
    except (subprocess.CalledProcessError, FileNotFoundError):
        missing_packages.append('pyinstaller')
        print("✗ pyinstaller")

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
