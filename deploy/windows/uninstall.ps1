# ServerGuard Agent Windows PowerShell 卸载脚本
# 用法: powershell -ExecutionPolicy Bypass -File uninstall.ps1

$ErrorActionPreference = "Stop"
$InstallDir = "C:\Program Files\ServerGuard"
$ServiceName = "ServerGuard"

Write-Host "=== ServerGuard Agent 卸载程序 ===" -ForegroundColor Cyan

# 检查管理员权限
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "错误: 需要管理员权限运行此脚本" -ForegroundColor Red
    exit 1
}

# 停止服务
Write-Host "停止 Windows 服务..." -ForegroundColor Yellow
try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
Start-Sleep -Seconds 2

# 删除服务
Write-Host "删除 Windows 服务..." -ForegroundColor Yellow
sc.exe delete $ServiceName | Out-Null

# 删除防火墙规则
Write-Host "删除防火墙规则..." -ForegroundColor Yellow
netsh advfirewall firewall delete rule name="ServerGuard Agent" | Out-Null

# 删除安装目录
Write-Host "删除安装目录..." -ForegroundColor Yellow
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
}

# 删除注册表
Write-Host "清理注册表..." -ForegroundColor Yellow
Remove-ItemProperty -Path "HKLM:\SOFTWARE\ServerGuard" -Name "InstallPath" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKLM:\SOFTWARE\ServerGuard" -Name "Version" -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\ServerGuard" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== 卸载完成 ===" -ForegroundColor Green