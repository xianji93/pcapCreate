@echo off
chcp 65001 >nul
echo 启动PCAP生成工具...

REM 尝试直接运行Python
python main.py
if errorlevel 1 (
    echo.
    echo 如果出现模块导入错误，请先运行：
    echo pip install scapy
    echo.
    pause
)
