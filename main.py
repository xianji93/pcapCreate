#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP生成工具主程序
支持Windows 7，可生成包含以太网、IP（v4/v6）、TCP/UDP的网络包
"""

import sys
import os
from gui.main_window import PcapGeneratorGUI

def main():
    """主函数"""
    try:
        app = PcapGeneratorGUI()
        app.run()
    except Exception as e:
        print(f"程序启动失败: {e}")
        input("按回车键退出...")
        sys.exit(1)

if __name__ == "__main__":
    main()
