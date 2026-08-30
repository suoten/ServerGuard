// ServerGuard WebShell Detection YARA Rules
// Covers PHP/JSP/ASP/Python/Perl webshells
// 仅保留高危组合模式，禁用纯函数名/纯混淆模式以避免误报

rule php_eval_base64 {
    strings:
        $s = /eval\s*\(\s*base64_decode\s*\(/ nocase
    condition:
        $s
}

rule php_assert_post {
    strings:
        $s = /assert\s*\(\s*\$_POST\s*\[/ nocase
    condition:
        $s
}

rule php_eval_get {
    strings:
        $s = /eval\s*\(\s*\$_GET\s*\[/ nocase
    condition:
        $s
}

rule php_gzuncompress_b64 {
    strings:
        $s = /gzuncompress\s*\(\s*base64_decode\s*\(/ nocase
    condition:
        $s
}

rule php_eval_request {
    strings:
        $s = /eval\s*\(\s*\$_REQUEST\s*\[/ nocase
    condition:
        $s
}

rule php_create_function {
    strings:
        // 收紧：要求 create_function + 用户输入在同一行 80 字符内
        // 旧规则只匹配 create_function(，vendor 库中正常使用会误报
        $a = /create_function\s*\([^\n]{0,80}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $b = /\$_(GET|POST|REQUEST|COOKIE)[^\n]{0,80}create_function\s*\(/ nocase
    condition:
        $a or $b
}

rule php_preg_replace_eval {
    strings:
        $s = /preg_replace\s*\(.{0,10}\/e[\"']/ nocase
    condition:
        $s
}

rule php_variable_function {
    strings:
        $s = /\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    condition:
        $s
}

rule php_system_exec_input {
    strings:
        $s = /\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        $s
}

rule jsp_runtime_exec {
    strings:
        $s = /Runtime\.getRuntime\s*\(\s*\)\.exec/ nocase
    condition:
        $s
}

rule jsp_process_builder {
    strings:
        $s = /ProcessBuilder\s*\(/ nocase
    condition:
        $s
}

rule asp_execute {
    strings:
        $s = /Server\.Execute\s*\(/ nocase
    condition:
        $s
}

rule asp_eval {
    strings:
        $s = /ExecuteGlobal\s*\(/ nocase
    condition:
        $s
}

rule python_exec_open {
    strings:
        $s = /\bexec\s*\(\s*open\s*\(/ nocase
    condition:
        $s
}

rule python_os_system_input {
    strings:
        $s = /os\.system\s*\(\s*(input|sys\.argv)/ nocase
    condition:
        $s
}

// python_subprocess_shell 规则已移除：
// Python Web 应用（Django/Flask/Tornado）中 subprocess + shell=True + request./base64 是正常模式，
// 导致所有 Python 后端源码被误报为 Webshell。
// Python Webshell 检测由 scanCodeFiles 中的正则模式（危险函数 + 用户输入）覆盖。

// 已知 webshell 名称特征（收紧：去掉过短/过于通用的名称）
rule c99_shell {
    strings:
        $s = /c99\s*shell|c99shell/ nocase
    condition:
        $s
}

rule r57_shell {
    strings:
        $s = /r57\s*shell|r57shell/ nocase
    condition:
        $s
}

rule b374k_shell {
    strings:
        $s = /b374k/ nocase
    condition:
        $s
}

rule china_chopper {
    strings:
        $s = /chopper|caidao/ nocase
    condition:
        $s
}

rule weevely_shell {
    strings:
        $s = /weevely/ nocase
    condition:
        $s
}

rule phpspy_shell {
    strings:
        $s = /phpspy/ nocase
    condition:
        $s
}

// webshell 组合特征（要求多个特征同时出现才报告）
rule webshell_base64_eval_combo {
    strings:
        // 收紧：要求 base64_decode 和 eval 在同一行 80 字符内出现
        // 旧规则只要求文件中同时存在两个函数，vendor 库中分散使用会误报
        $a = /base64_decode\s*\([^\n]{0,60}eval\s*\(/ nocase
        $b = /eval\s*\([^\n]{0,60}base64_decode\s*\(/ nocase
    condition:
        $a or $b
}

rule webshell_packer {
    strings:
        // 收紧：要求 pack(H*) + 命令执行函数在同一行 80 字符内出现
        // 旧规则只匹配 pack(H*，workerman/TCPDF 中正常的二进制打包会误报
        $a = /pack\s*\([^\n]{0,30}H\*[^\n]{0,40}(?:eval|system|exec|passthru|popen|proc_open|assert)\s*\(/ nocase
        $b = /(?:eval|system|exec|passthru|popen|proc_open|assert)\s*\([^\n]{0,40}pack\s*\([^\n]{0,30}H\*/ nocase
    condition:
        $a or $b
}

// 已禁用的高误报规则：
// - php_system_exec: 只匹配函数名，正常PHP代码中 system/exec 太常见
// - webshell_obfuscated: 只匹配3个连续\xHH，正常JS/PHP都会触发
// - webshell_php_info: phpinfo() 在正常调试代码中常见
// - webshell_disk_total: disk_total_space() 在正常监控代码中常见
// - webshell_str_rot13: str_rot13() 在正常代码中使用
// - webshell_convert_uuencode: convert_uuencode() 在正常代码中使用
// - perl_eval: eval{} 在正常Perl代码中极其常见
// - xshell_shell: "xshell" 太通用了
