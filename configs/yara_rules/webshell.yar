// ServerGuard WebShell Detection YARA Rules
// Covers PHP/JSP/ASP/Python/Perl webshells

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

rule php_system_exec {
    strings:
        $s = /\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(/ nocase
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

rule php_str_replace_rot13 {
    strings:
        $s = /str_replace\s*\(.{0,20}rot13/ nocase
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
        $s = /create_function\s*\(/ nocase
    condition:
        $s
}

rule php_preg_replace_eval {
    strings:
        $s = /preg_replace\s*\(.{0,10}e.{0,5}\)/ nocase
    condition:
        $s
}

rule php_variable_function {
    strings:
        $s = /\$\w+\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
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

rule python_os_system {
    strings:
        $s = /os\.system\s*\(/ nocase
    condition:
        $s
}

rule python_subprocess_shell {
    strings:
        $s = /subprocess\.\w+\(.*shell\s*=\s*True/ nocase
    condition:
        $s
}

rule perl_eval {
    strings:
        $s = /\beval\s*\{/ nocase
    condition:
        $s
}

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

rule xshell_shell {
    strings:
        $s = /xshell/ nocase
    condition:
        $s
}

rule webshell_php_info {
    strings:
        $s = /phpinfo\s*\(\s*\)/ nocase
    condition:
        $s
}

rule webshell_disk_total {
    strings:
        $s = /disk_total_space\s*\(/ nocase
    condition:
        $s
}

rule webshell_packer {
    strings:
        $s = /pack\s*\(.{0,30}H\*/ nocase
    condition:
        $s
}

rule webshell_obfuscated {
    strings:
        $s = /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/ nocase
    condition:
        $s
}

rule webshell_base64_eval {
    strings:
        $s = /base64_decode\s*\(.{0,50}eval/ nocase
    condition:
        $s
}

rule webshell_str_rot13 {
    strings:
        $s = /str_rot13\s*\(/ nocase
    condition:
        $s
}

rule webshell_convert_uuencode {
    strings:
        $s = /convert_uuencode\s*\(/ nocase
    condition:
        $s
}