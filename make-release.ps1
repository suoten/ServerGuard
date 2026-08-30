# ServerGuard 发布打包脚本
# 用法: powershell -ExecutionPolicy Bypass -File make-release.ps1
# 产出: release/serverguard-<platform>.tar.gz (每个包包含二进制+安装脚本+配置+文档)

param(
    [string]$Version = "0.3.0"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  ServerGuard v$Version Release Builder" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. 构建前端
Write-Host "[1/4] Building web frontend..." -ForegroundColor Green
Push-Location web
$proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c npx vite build" -NoNewWindow -Wait -PassThru -RedirectStandardError "NUL"
Pop-Location
if (-not (Test-Path "internal/hub/panel/dist/index.html")) {
    Write-Host "ERROR: Web build failed" -ForegroundColor Red
    exit 1
}
Write-Host "  Frontend built OK" -ForegroundColor DarkGray

# 2. 编译三个平台的二进制 (CGO_ENABLED=0 纯Go，无C依赖)
#    组件: agent(采集/自愈) + hub(面板与扫描中枢) + sgctl(运维CLI)
#    注意: hub 必须随包发布——攻击预警/网站安全等扫描逻辑运行在 Hub 进程内，
#    只升级 agent 不会更新任何检测能力
Write-Host "[2/4] Cross-compiling binaries..." -ForegroundColor Green

$platforms = @(
    @{ GOOS="linux";   GOARCH="amd64" },
    @{ GOOS="linux";   GOARCH="arm64" },
    @{ GOOS="windows"; GOARCH="amd64" }
)

$components = @(
    @{ Cmd="./cmd/serverguard-agent/"; Base="serverguard-agent" },
    @{ Cmd="./cmd/serverguard-hub/";   Base="serverguard-hub" },
    @{ Cmd="./cmd/sgctl/";             Base="sgctl" }
)

$binaries = @{}
foreach ($p in $platforms) {
    $env:GOOS = $p.GOOS
    $env:GOARCH = $p.GOARCH
    $env:CGO_ENABLED = "0"
    foreach ($c in $components) {
        $ext = ""
        if ($p.GOOS -eq "windows") { $ext = ".exe" }
        $key = "$($c.Base)-$($p.GOOS)-$($p.GOARCH)$ext"
        $out = "dist/$key"
        Write-Host "  Building $($c.Base) $($p.GOOS)/$($p.GOARCH)..." -ForegroundColor DarkGray
        # Go outputs diagnostics to stderr; temporarily relax ErrorActionPreference
        # to avoid PowerShell treating stderr output as a terminating error
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & go build -ldflags="-s -w" -o $out $c.Cmd 2>&1 | Out-Null
        $buildExit = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP
        if ($buildExit -ne 0) {
            Write-Host "ERROR: Build failed for $key (exit $buildExit)" -ForegroundColor Red
            exit 1
        }
        if (-not (Test-Path $out)) {
            Write-Host "ERROR: Build failed for $key" -ForegroundColor Red
            exit 1
        }
        $binaries[$key] = $out
    }
}

$env:GOOS = ""
$env:GOARCH = ""
$env:CGO_ENABLED = ""
Write-Host "  All binaries built OK" -ForegroundColor DarkGray

# 3. 准备打包目录
Write-Host "[3/4] Preparing release packages..." -ForegroundColor Green

# 清理旧的
if (Test-Path "release") { Remove-Item -Recurse -Force "release" -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path "release" -Force | Out-Null

# 公共文件（每个包都包含）
$commonFiles = @(
    @{ Src="deploy/install.sh";                  Dst="install.sh" },
    @{ Src="deploy/uninstall.sh";                Dst="uninstall.sh" },
    @{ Src="deploy/serverguard-agent.service";   Dst="serverguard-agent.service" },
    @{ Src="configs/serverguard-agent.yaml";      Dst="config.yaml" },
    @{ Src="README.md";                           Dst="README.md" }
)

# 为每个平台创建 zip 包（Linux 也能用 unzip 解压）
# 每个包都包含全部三个组件：agent(采集/自愈+面板)、hub(多服务器中枢)、sgctl(CLI)
# install.sh 会自动检测并安装存在的二进制
foreach ($p in $platforms) {
    $tag = "$($p.GOOS)-$($p.GOARCH)"
    $ext = ""
    if ($p.GOOS -eq "windows") { $ext = ".exe" }
    $pkgDir = "release/serverguard-$tag-pkg"
    New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null

    # 复制三个组件的二进制
    foreach ($c in $components) {
        $srcKey = "$($c.Base)-$tag$ext"
        Copy-Item $binaries[$srcKey] "$pkgDir/$($c.Base)$ext"
    }

    # 复制公共文件
    foreach ($f in $commonFiles) {
        if (Test-Path $f.Src) {
            Copy-Item $f.Src "$pkgDir/$($f.Dst)"
        }
    }

    # 复制安全规则文件（YARA 规则和 CIS Benchmark）
    if (Test-Path "configs/yara_rules") {
        New-Item -ItemType Directory -Path "$pkgDir/configs/yara_rules" -Force | Out-Null
        Copy-Item -Path "configs/yara_rules/*" -Destination "$pkgDir/configs/yara_rules/" -Recurse -Force
    }
    if (Test-Path "configs/cis_benchmark") {
        New-Item -ItemType Directory -Path "$pkgDir/configs/cis_benchmark" -Force | Out-Null
        Copy-Item -Path "configs/cis_benchmark/*" -Destination "$pkgDir/configs/cis_benchmark/" -Recurse -Force
    }

    # 打 zip 包
    $zipball = "release/serverguard-$Version-$tag.zip"
    Write-Host "  Creating $zipball..." -ForegroundColor DarkGray
    Compress-Archive -Path "$pkgDir/*" -DestinationPath $zipball -Force

    $size = [math]::Round((Get-Item $zipball).Length / 1MB, 1)
    Write-Host "  -> $zipball ($size MB)" -ForegroundColor Yellow

    # 清理临时目录（中文路径下 Remove-Item 可能因编码问题失败，忽略错误不影响发布）
    if (Test-Path $pkgDir) {
        Remove-Item -Recurse -Force $pkgDir -ErrorAction SilentlyContinue
    }
}

# 生成校验文件
Write-Host "[4/4] Generating checksums..." -ForegroundColor Green
Push-Location release
$hashes = Get-ChildItem -Filter "*.zip" | ForEach-Object {
    $hash = (Get-FileHash $_.Name -Algorithm SHA256).Hash
    "$hash  $($_.Name)"
}
$hashes | Out-File -Encoding ASCII -FilePath "checksums.txt"
Pop-Location

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host "  Release packages created:" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Get-ChildItem release | ForEach-Object {
    $size = if ($_.Length -gt 1MB) { "$([math]::Round($_.Length/1MB,1)) MB" } else { "$([math]::Round($_.Length/1KB,0)) KB" }
    Write-Host "  release/$($_.Name)  ($size)" -ForegroundColor White
}
Write-Host ""
Write-Host "Each package contains:" -ForegroundColor Cyan
Write-Host "  serverguard-agent        <- agent binary (采集/自愈)" -ForegroundColor DarkGray
Write-Host "  serverguard-hub          <- hub binary (面板+扫描中枢，必须更新!)" -ForegroundColor DarkGray
Write-Host "  sgctl                    <- 运维 CLI" -ForegroundColor DarkGray
Write-Host "  install.sh               <- one-click installer" -ForegroundColor DarkGray
Write-Host "  uninstall.sh             <- uninstaller" -ForegroundColor DarkGray
Write-Host "  serverguard-agent.service <- systemd config" -ForegroundColor DarkGray
Write-Host "  config.yaml              <- config template" -ForegroundColor DarkGray
Write-Host "  README.md                <- full documentation" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Linux deploy: upload zip -> unzip -> bash install.sh" -ForegroundColor Yellow
Write-Host "  install.sh 只安装 agent；hub/sgctl 需手动替换同名二进制后重启服务" -ForegroundColor Yellow
Write-Host ""
