package enrich

import "regexp"

// Rule is a single detection. The first matching rule sets an event's category,
// score, and MITRE mapping; every matching rule contributes its tags.
//
// Tags carry deliberate Japanese/English pairs. They are indexed alongside the
// log text, which is what lets an English "Failed password" line retrieve a
// Japanese JPCERT advisory about ブルートフォース攻撃 even when the embedding model
// is weak on short, jargon-heavy strings. It is a cheap lexical bridge under the
// semantic one.
//
// Process, when non-empty, restricts the rule to those syslog tags, which stops a
// generic pattern like "session opened" from firing on unrelated daemons.
type Rule struct {
	Name     string
	Category string
	Score    int
	Outcome  string
	MITRE    []string
	Tags     []string
	Process  []string
	Pattern  *regexp.Regexp
}

// Categories used across the system. The dashboard groups by these.
const (
	CatAuth      = "authentication"
	CatPrivilege = "privilege-escalation"
	CatPersist   = "persistence"
	CatExecution = "execution"
	CatEvasion   = "defense-evasion"
	CatRecon     = "reconnaissance"
	CatNetwork   = "network"
	CatImpact    = "impact"
	CatScheduled = "scheduled-task"
	CatSystem    = "system"
	CatPolicy    = "policy"
	CatChange    = "configuration-change"
	CatIncident  = "incident"
	CatUnknown   = "uncategorised"
)

// rules is ordered most-specific first.
var rules = []Rule{
	// ---------------------------------------------------------------- execution
	{
		Name:     "reverse_shell_bash_devtcp",
		Category: CatExecution,
		Score:    96,
		Outcome:  "attempt",
		MITRE:    []string{"T1059.004", "T1071.001"},
		Tags:     []string{"reverse-shell", "リバースシェル", "c2", "遠隔操作"},
		Pattern:  regexp.MustCompile(`(?i)(bash|sh|zsh)\s+-i\s*>&?\s*/dev/(tcp|udp)/|nc\s+(-[a-z]*e|--exec)\s`),
	},
	{
		Name:     "curl_pipe_shell",
		Category: CatExecution,
		Score:    88,
		Outcome:  "attempt",
		MITRE:    []string{"T1059.004", "T1105"},
		Tags:     []string{"remote-code-execution", "任意コード実行", "dropper", "マルウェア配布"},
		Pattern:  regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`),
	},
	{
		Name:     "cryptominer_indicator",
		Category: CatImpact,
		Score:    92,
		Outcome:  "success",
		MITRE:    []string{"T1496"},
		Tags:     []string{"cryptomining", "クリプトマイニング", "resource-hijacking", "リソース不正利用"},
		Pattern:  regexp.MustCompile(`(?i)\b(xmrig|minerd|cpuminer|stratum\+tcp://|nanopool|supportxmr)\b`),
	},
	{
		Name:     "log_tampering",
		Category: CatEvasion,
		Score:    90,
		Outcome:  "attempt",
		MITRE:    []string{"T1070.002"},
		Tags:     []string{"anti-forensics", "証跡削除", "log-tampering", "ログ改ざん"},
		Pattern:  regexp.MustCompile(`(?i)(rm\s+(-[a-z]+\s+)*/var/log|truncate\s+-s\s*0\s+/var/log|journalctl\s+--vacuum|>\s*/var/log/(auth|sys)log|history\s+-c)`),
	},

	// ----------------------------------------------------------- authentication
	{
		Name:     "ssh_failed_password",
		Category: CatAuth,
		Score:    46,
		Outcome:  "failure",
		MITRE:    []string{"T1110.001"},
		Tags:     []string{"brute-force", "ブルートフォース", "auth-failure", "認証失敗", "ssh"},
		Process:  []string{"sshd"},
		Pattern:  regexp.MustCompile(`Failed (?:password|keyboard-interactive/pam|publickey) for (?:invalid user )?(?P<user>[^\s]+) from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)`),
	},
	{
		Name:     "ssh_invalid_user",
		Category: CatAuth,
		Score:    52,
		Outcome:  "failure",
		MITRE:    []string{"T1110.001", "T1589.001"},
		Tags:     []string{"user-enumeration", "ユーザー列挙", "brute-force", "ブルートフォース", "ssh"},
		Process:  []string{"sshd"},
		Pattern:  regexp.MustCompile(`Invalid user (?P<user>[^\s]*) from (?P<ip>[0-9a-fA-F.:]+)(?: port (?P<port>\d+))?`),
	},
	{
		Name:     "ssh_max_auth_attempts",
		Category: CatAuth,
		Score:    64,
		Outcome:  "failure",
		MITRE:    []string{"T1110.001"},
		Tags:     []string{"brute-force", "ブルートフォース", "ssh"},
		Process:  []string{"sshd"},
		Pattern:  regexp.MustCompile(`(?i)(maximum authentication attempts exceeded|too many authentication failures)`),
	},
	{
		Name:     "ssh_reverse_dns_mismatch",
		Category: CatRecon,
		Score:    58,
		Outcome:  "suspicious",
		MITRE:    []string{"T1110.001"},
		Tags:     []string{"spoofing", "なりすまし", "break-in", "侵入試行"},
		Pattern:  regexp.MustCompile(`POSSIBLE BREAK-IN ATTEMPT`),
	},
	{
		Name:     "ssh_accepted_login",
		Category: CatAuth,
		Score:    26,
		Outcome:  "success",
		MITRE:    []string{"T1078.003"},
		Tags:     []string{"successful-login", "ログイン成功", "valid-accounts", "正規アカウント", "ssh"},
		Process:  []string{"sshd"},
		Pattern:  regexp.MustCompile(`Accepted (?P<method>password|publickey|keyboard-interactive/pam|none) for (?P<user>[^\s]+) from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)`),
	},
	{
		Name:     "ssh_preauth_disconnect",
		Category: CatRecon,
		Score:    18,
		Outcome:  "failure",
		MITRE:    []string{"T1595"},
		Tags:     []string{"scanning", "スキャン", "probe", "探索", "ssh"},
		Process:  []string{"sshd"},
		Pattern:  regexp.MustCompile(`(?:Received disconnect from|Connection (?:closed|reset) by(?: authenticating user \S+)?) (?P<ip>[0-9a-fA-F.:]+)(?: port (?P<port>\d+))?.*\[preauth\]`),
	},
	{
		Name:     "pam_authentication_failure",
		Category: CatAuth,
		Score:    44,
		Outcome:  "failure",
		MITRE:    []string{"T1110"},
		Tags:     []string{"auth-failure", "認証失敗", "pam"},
		Pattern:  regexp.MustCompile(`pam_unix\([^)]+:auth\): authentication failure;.*?(?:rhost=(?P<ip>[0-9a-fA-F.:]*))?.*?(?:user=(?P<user>\S+))?$`),
	},

	// ------------------------------------------------------ privilege escalation
	{
		Name:     "sudo_not_in_sudoers",
		Category: CatPrivilege,
		Score:    72,
		Outcome:  "failure",
		MITRE:    []string{"T1548.003"},
		Tags:     []string{"privilege-escalation", "権限昇格", "sudo", "policy-violation", "ポリシー違反"},
		Pattern:  regexp.MustCompile(`(?P<user>\S+) : user NOT in sudoers`),
	},
	{
		Name:     "sudo_incorrect_password",
		Category: CatPrivilege,
		Score:    62,
		Outcome:  "failure",
		MITRE:    []string{"T1548.003"},
		Tags:     []string{"privilege-escalation", "権限昇格", "sudo", "auth-failure", "認証失敗"},
		Pattern:  regexp.MustCompile(`(?P<user>\S+) : \d+ incorrect password attempts?`),
	},
	{
		Name:     "sudo_command_executed",
		Category: CatPrivilege,
		Score:    32,
		Outcome:  "success",
		MITRE:    []string{"T1548.003"},
		Tags:     []string{"sudo", "権限昇格", "privileged-command", "特権コマンド"},
		Process:  []string{"sudo"},
		Pattern:  regexp.MustCompile(`(?P<user>\S+) : TTY=\S+ ; PWD=\S+ ; USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.+)$`),
	},
	{
		Name:     "su_failed",
		Category: CatPrivilege,
		Score:    58,
		Outcome:  "failure",
		MITRE:    []string{"T1548.003"},
		Tags:     []string{"privilege-escalation", "権限昇格", "su", "auth-failure", "認証失敗"},
		Pattern:  regexp.MustCompile(`FAILED SU \(to (?P<target_user>\S+)\) (?P<user>\S+)`),
	},
	{
		Name:     "pkexec_polkit_abuse",
		Category: CatPrivilege,
		Score:    86,
		Outcome:  "attempt",
		MITRE:    []string{"T1068"},
		Tags:     []string{"pwnkit", "権限昇格", "polkit", "exploit", "脆弱性攻撃", "CVE-2021-4034"},
		Pattern:  regexp.MustCompile(`(?i)pkexec.*(?:cannot|refus|The value for the SHELL variable was not found|GCONV_PATH)`),
	},

	// ------------------------------------------------------------- persistence
	{
		Name:     "new_user_created",
		Category: CatPersist,
		Score:    68,
		Outcome:  "success",
		MITRE:    []string{"T1136.001"},
		Tags:     []string{"persistence", "永続化", "account-creation", "アカウント作成"},
		Pattern:  regexp.MustCompile(`new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)`),
	},
	{
		Name:     "user_added_to_privileged_group",
		Category: CatPersist,
		Score:    74,
		Outcome:  "success",
		MITRE:    []string{"T1098"},
		Tags:     []string{"persistence", "永続化", "group-membership", "グループ変更", "privilege-escalation", "権限昇格"},
		Pattern:  regexp.MustCompile(`add '(?P<user>[^']+)' to group '(?P<group>sudo|admin|wheel|docker|root)'`),
	},
	{
		Name:     "authorized_keys_modified",
		Category: CatPersist,
		Score:    78,
		Outcome:  "success",
		MITRE:    []string{"T1098.004"},
		Tags:     []string{"persistence", "永続化", "ssh-key", "SSH鍵", "backdoor", "バックドア"},
		Pattern:  regexp.MustCompile(`(?i)authorized_keys`),
	},
	{
		Name:     "systemd_unit_installed",
		Category: CatPersist,
		Score:    56,
		Outcome:  "success",
		MITRE:    []string{"T1543.002"},
		Tags:     []string{"persistence", "永続化", "systemd", "service-install", "サービス登録"},
		Pattern:  regexp.MustCompile(`(?i)(Created symlink /etc/systemd/system|Reloading|enabled)\b.*\.(service|timer)`),
	},

	// ------------------------------------------------------------------ network
	{
		Name:     "ufw_block",
		Category: CatNetwork,
		Score:    30,
		Outcome:  "blocked",
		MITRE:    []string{"T1595.001"},
		Tags:     []string{"firewall-block", "ファイアウォール遮断", "port-scan", "ポートスキャン"},
		Pattern:  regexp.MustCompile(`\[UFW (?:BLOCK|AUDIT)\].*?SRC=(?P<ip>[0-9a-fA-F.:]+) DST=(?P<dest_ip>[0-9a-fA-F.:]+).*?PROTO=(?P<proto>\S+)(?: SPT=(?P<port>\d+))?(?: DPT=(?P<dest_port>\d+))?`),
	},
	{
		Name:     "iptables_drop",
		Category: CatNetwork,
		Score:    28,
		Outcome:  "blocked",
		MITRE:    []string{"T1595.001"},
		Tags:     []string{"firewall-block", "ファイアウォール遮断"},
		Pattern:  regexp.MustCompile(`(?i)IN=\S+ OUT=\S* .*SRC=(?P<ip>[0-9a-fA-F.:]+).*DPT=(?P<dest_port>\d+)`),
	},

	// ----------------------------------------------------------- scheduled task
	{
		Name:     "cron_job_executed",
		Category: CatScheduled,
		Score:    14,
		Outcome:  "success",
		MITRE:    []string{"T1053.003"},
		Tags:     []string{"cron", "定期実行", "scheduled-task", "スケジュールタスク"},
		Process:  []string{"CRON", "cron", "crond"},
		Pattern:  regexp.MustCompile(`\((?P<user>[^)]+)\) CMD \((?P<command>.*)\)$`),
	},
	{
		Name:     "crontab_modified",
		Category: CatPersist,
		Score:    60,
		Outcome:  "success",
		MITRE:    []string{"T1053.003"},
		Tags:     []string{"persistence", "永続化", "cron", "定期実行"},
		Pattern:  regexp.MustCompile(`\((?P<user>[^)]+)\) (?:REPLACE|BEGIN EDIT|END EDIT|DELETE) \((?P<target_user>\S+)\)`),
	},

	// ------------------------------------------------------------------- policy
	{
		Name:     "selinux_apparmor_denied",
		Category: CatPolicy,
		Score:    42,
		Outcome:  "blocked",
		MITRE:    []string{"T1211"},
		Tags:     []string{"mandatory-access-control", "強制アクセス制御", "denied", "アクセス拒否"},
		Pattern:  regexp.MustCompile(`(?i)(avc:\s+denied|apparmor="DENIED")`),
	},
	{
		Name:     "auditd_disabled",
		Category: CatEvasion,
		Score:    84,
		Outcome:  "success",
		MITRE:    []string{"T1562.001"},
		Tags:     []string{"defense-evasion", "防御回避", "audit-disabled", "監査無効化"},
		Pattern:  regexp.MustCompile(`(?i)(audit(d)?.*(disabled|stopped|halted)|auditd.*Init complete.*enabled 0)`),
	},

	// ------------------------------------------------------------------- system
	{
		Name:     "oom_kill",
		Category: CatSystem,
		Score:    54,
		Outcome:  "failure",
		MITRE:    []string{"T1499.001"},
		Tags:     []string{"out-of-memory", "メモリ枯渇", "availability", "可用性"},
		Pattern:  regexp.MustCompile(`Out of memory: Kill(?:ed)? process (?P<pid>\d+) \((?P<proc>[^)]+)\)`),
	},
	{
		Name:     "segfault",
		Category: CatSystem,
		Score:    46,
		Outcome:  "failure",
		MITRE:    []string{"T1499.004"},
		Tags:     []string{"crash", "クラッシュ", "memory-corruption", "メモリ破壊", "possible-exploit", "攻撃の可能性"},
		Pattern:  regexp.MustCompile(`(?P<proc>\S+)\[(?P<pid>\d+)\]: segfault at (?P<addr>[0-9a-f]+)`),
	},
	{
		Name:     "service_failed",
		Category: CatSystem,
		Score:    36,
		Outcome:  "failure",
		Tags:     []string{"service-failure", "サービス障害", "availability", "可用性"},
		Pattern:  regexp.MustCompile(`(?i)(Failed to start |entered failed state|Main process exited, code=exited, status=[1-9])`),
	},
	{
		Name:     "disk_error",
		Category: CatSystem,
		Score:    50,
		Outcome:  "failure",
		Tags:     []string{"hardware", "ハードウェア", "disk-error", "ディスク障害"},
		Pattern:  regexp.MustCompile(`(?i)(I/O error|SMART error|EXT4-fs error|critical medium error)`),
	},

	// ------------------------------------------------------ configuration change
	{
		Name:     "package_change",
		Category: CatChange,
		Score:    12,
		Outcome:  "success",
		Tags:     []string{"package-management", "パッケージ管理", "change", "変更"},
		Pattern:  regexp.MustCompile(`(?i)\b(apt-get|apt|dpkg|yum|dnf)\b.*\b(install|remove|purge|upgrade)\b`),
	},
	{
		Name:     "session_opened",
		Category: CatAuth,
		Score:    16,
		Outcome:  "success",
		Tags:     []string{"session", "セッション"},
		Pattern:  regexp.MustCompile(`session opened for user (?P<user>\S+)`),
	},
	{
		Name:     "session_closed",
		Category: CatAuth,
		Score:    10,
		Outcome:  "success",
		Tags:     []string{"session", "セッション"},
		Pattern:  regexp.MustCompile(`session closed for user (?P<user>\S+)`),
	},
}

// Rules exposes the compiled rule set (read-only) for tests and documentation.
func Rules() []Rule { return rules }
