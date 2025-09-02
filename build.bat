@echo off
chcp 65001 >nul
echo PCAP生成工具构建脚本
echo ========================

echo 检查Python环境...
python --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 未找到Python，请先安装Python 3.7或更高版本
    pause
    exit /b 1
)

echo 安装依赖包...
pip install -r requirements.txt
if errorlevel 1 (
    echo 错误: 依赖包安装失败
    pause
    exit /b 1
)

echo 开始构建...
python build.py
if errorlevel 1 (
    echo 错误: 构建失败
    pause
    exit /b 1
)

echo.
echo 构建完成! 可执行文件位于 dist\PcapGenerator.exe
pause
