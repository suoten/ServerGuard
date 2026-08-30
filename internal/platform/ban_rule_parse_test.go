package platform

import "testing"

// parseBanRuleLine 回归：从 iptables -L --line-numbers 输出中正确识别本工具规则与到期时间。
// 错误解析会导致误删他人规则（宝塔的防火墙规则）或永不过期堆积；
// 历史事故：UnbanIP/ListBanned 取错列（fields[3] 是 "--" 分隔符）导致解封与封禁列表完全失效。
func TestParseBanRuleLine(t *testing.T) {
	cases := []struct {
		name       string
		line       string
		wantNum    string
		wantIP     string
		wantExpire int64
		wantOK     bool
	}{
		{
			name:       "带过期的标准规则",
			line:       `1       DROP       tcp  --  203.0.113.5        0.0.0.0/0            /* serverguard-attackwarn:exp=1756000000:attack:xss */`,
			wantNum:    "1",
			wantIP:     "203.0.113.5",
			wantExpire: 1756000000,
			wantOK:     true,
		},
		{
			name:       "永久规则（exp=0）",
			line:       `7       DROP       all  --  198.51.100.9       0.0.0.0/0            /* serverguard:exp=0:manual */`,
			wantNum:    "7",
			wantIP:     "198.51.100.9",
			wantExpire: 0,
			wantOK:     true,
		},
		{
			name:       "旧格式无 exp 字段视为永久",
			line:       `3       DROP       tcp  --  203.0.113.6        anywhere             /* serverguard-attackwarn:attack:xss */`,
			wantNum:    "3",
			wantIP:     "203.0.113.6",
			wantExpire: 0,
			wantOK:     true,
		},
		{
			name:   "非本工具规则必须拒绝",
			line:   `5       DROP       tcp  --  203.0.113.7        anywhere             tcp dpt:8888`,
			wantOK: false,
		},
		{
			name:   "链头行不是规则",
			line:   `Chain INPUT (policy ACCEPT)`,
			wantOK: false,
		},
		{
			name:   "表头行不是规则",
			line:   `num   target     prot opt source               destination`,
			wantOK: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			num, ip, expire, ok := parseBanRuleLine(c.line)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if !c.wantOK {
				return
			}
			if num != c.wantNum {
				t.Fatalf("lineNum = %q, want %q", num, c.wantNum)
			}
			if ip != c.wantIP {
				t.Fatalf("ip = %q, want %q", ip, c.wantIP)
			}
			if expire != c.wantExpire {
				t.Fatalf("expire = %d, want %d", expire, c.wantExpire)
			}
		})
	}
}
