# ServerGuard Agent Windows PowerShell 安装脚本
# 用法: powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = "Stop"
$InstallDir = "C:\Program Files\ServerGuard"
$ServiceName = "ServerGuard"
$BinaryName = "serverguard-agent.exe"
$CtlName = "sgctl.exe"

Write-Host "=== ServerGuard Agent 安装程序 ===" -ForegroundColor Cyan

# 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "错误: 需要管理员权限运行此脚本" -ForegroundColor Red
    exit 1
}

# 检查 64 位
if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Host "错误: ServerGuard Agent 需要 64 位 Windows 系统" -ForegroundColor Red
    exit 1
}

# 创建安装目录
Write-Host "创建安装目录: $InstallDir" -ForegroundColor Yellow
if (Test-Path $InstallDir) {
    Write-Host "检测到已有安装，正在停止服务..." -ForegroundColor Yellow
    try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
    try { sc.exe delete $ServiceName | Out-Null } catch {}
    Start-Sleep -Seconds 2
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\configs" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\logs" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\data" | Out-Null

# 复制文件
Write-Host "复制程序文件..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$binDir = Join-Path $scriptDir "..\bin"

if (Test-Path (Join-Path $binDir $BinaryName)) {
    Copy-Item (Join-Path $binDir $BinaryName) $InstallDir -Force
} else {
    Write-Host "错误: 找不到 $BinaryName，请先运行 go build" -ForegroundColor Red
    exit 1
}

if (Test-Path (Join-Path $binDir $CtlName)) {
    Copy-Item (Join-Path $binDir $CtlName) $InstallDir -Force
}

if (Test-Path (Join-Path $scriptDir "..\configs")) {
    Copy-Item (Join-Path $scriptDir "..\configs\*") "$InstallDir\configs" -Recurse -Force
}

# 安装 Windows 服务
Write-Host "安装 Windows 服务..." -ForegroundColor Yellow
$binaryPath = Join-Path $InstallDir $BinaryName
sc.exe create $ServiceName binPath= "`"$binaryPath`" service run" start= auto displayname= "ServerGuard Agent" | Out-Null
sc.exe description $ServiceName "ServerGuard - 轻量级服务器自愈守护系统" | Out-Null

# 配置服务恢复策略
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

# 启动服务
Write-Host "启动服务..." -ForegroundColor Yellow
Start-Service -Name $ServiceName

# 添加防火墙规则
Write-Host "配置防火墙规则..." -ForegroundColor Yellow
netsh advfirewall firewall add rule name="ServerGuard Agent" dir=in action=allow program="$binaryPath" enable=yes | Out-Null

# 写入注册表
Set-ItemProperty -Path "HKLM:\SOFTWARE\ServerGuard" -Name "InstallPath" -Value $InstallDir -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\ServerGuard" -Name "Version" -Value "3.3.0" -Force

Write-Host ""
Write-Host "=== 安装完成 ===" -ForegroundColor Green
Write-Host "安装目录: $InstallDir"
Write-Host "服务名称: $ServiceName"
Write-Host "配置文件: $InstallDir\configs\"
Write-Host "日志目录: $InstallDir\logs\"
Write-Host "数据目录: $InstallDir\data\"
Write-Host ""
Write-Host "使用 sgctl 管理工具: $InstallDir\sgctl.exe"
Write-Host "查看服务状态: sc.exe query $ServiceName"
Write-Host "查看服务日志: sc.exe qc $ServiceName"