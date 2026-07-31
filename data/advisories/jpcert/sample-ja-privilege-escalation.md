---
id: sample-ja-privilege-escalation
title: "Linux における権限昇格の脆弱性および sudo の不正利用への対応について"
publisher: "JPCERT/CC 形式のサンプル文書（実在の公開文書ではありません）"
published: 2026-02-04
lang: ja
severity: high
cve: CVE-2021-4034
mitre: [T1068, T1548.003, T1078.003]
keywords:
  - 権限昇格
  - privilege escalation
  - ローカル権限昇格
  - local privilege escalation
  - polkit
  - pkexec
  - sudo
  - setuid
  - 特権コマンド
  - PwnKit
---

## 概要

Linux ホストにおける権限昇格は、侵入の「第二段階」に該当する攻撃手法です。
権限昇格の痕跡が記録されている場合、それ以前の段階で **すでに何らかの
アクセスが成立している** ことを意味します。したがって調査は「昇格が阻止された
か」だけでなく、「非特権シェルがどのように取得されたか」まで遡る必要があります。

## 主な手口

### 1. polkit pkexec の脆弱性（CVE-2021-4034 / PwnKit）

polkit の `pkexec` に存在するメモリ破壊の脆弱性により、任意のローカル
ユーザーが root 権限を取得できます。2009 年の polkit 初期リリースから
存在していた問題で、2022 年 1 月に修正されました。攻撃は極めて安定して
成功し、特別な条件を必要としません。

失敗した試行では、次のログが記録されます。

```
pkexec: The value for the SHELL variable was not found in the /etc/shells file
```

この行は正常な `pkexec` の利用では通常出力されないため、最も有用な指標です。

対策:

```bash
sudo apt-get update && sudo apt-get install --only-upgrade policykit-1
# 修正適用が困難な場合の暫定対応（正規の pkexec 利用が停止します）
sudo chmod 0755 /usr/bin/pkexec
```

### 2. sudo の不正利用（T1548.003）

侵害されたアカウントが sudo 権限を保有している場合、追加の脆弱性を必要と
せずに root 権限を取得できます。ログ上の痕跡は次のとおりです。

```
sudo[4100]: arron : TTY=pts/0 ; PWD=/home/arron ; USER=root ; COMMAND=/bin/bash
sudo[4150]: attacker : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh
sudo[4160]: attacker : 3 incorrect password attempts ; TTY=pts/1 ; USER=root
```

`user NOT in sudoers` は、sudo 権限を持たないアカウントが特権実行を試行した
ことを示し、正常な運用では発生しません。`incorrect password attempts` の連続も
同様に、アカウントの正当な利用者ではない可能性を示唆します。

### 3. setuid バイナリの追加

攻撃者は root 権限の取得後、再取得を容易にするため setuid バイナリを設置する
ことがあります。

```bash
sudo find / -perm -4000 -type f -newermt '-7 days' -ls 2>/dev/null
sudo find / -perm -4000 -type f -ls 2>/dev/null | sort -k11
```

`/tmp`、`/dev/shm`、`/var/tmp` 配下の setuid バイナシは、正常な構成では
存在しません。

## Unicode 制御文字を用いた偽装への注意

`sudo` の実行コマンドや監査ログの表示において、Unicode の双方向制御文字
（U+202E RIGHT-TO-LEFT OVERRIDE 等）が用いられている場合、**画面上の表示と
実際に実行されたコマンドが一致しない** 可能性があります（Trojan Source、
CVE-2021-42574 として知られる手法）。

ログ閲覧時には、制御文字を可視化した状態で確認してください。

```bash
sudo cat -v /var/log/auth.log | grep -a 'M-bM-^\|M-oM-;'
grep -aP '[\x{202a}-\x{202e}\x{2066}-\x{2069}]' /var/log/auth.log
```

ログ収集の段階で制御文字を無害化（エスケープ）する仕組みを導入することが
望ましく、これはログインジェクション（CWE-117）対策としても有効です。

## 調査手順

権限昇格の痕跡を確認した場合、次の順序で調査してください。

1. **sudoers 設定の確認**

   ```bash
   sudo visudo -c
   sudo grep -rv '^#\|^$' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
   ```

2. **特権グループのメンバーシップ確認**

   ```bash
   getent group sudo wheel adm docker
   ```

   `docker` グループへの所属は root 権限と同等です。見落としやすいため
   必ず確認してください。

3. **昇格前のアクセス経路の特定**
   認証ログ、Web アプリケーションのログ、低権限で動作しているサービスの
   ログを確認し、初期アクセスの経路を特定します。

4. **昇格後の活動の確認**
   永続化の設置、認証情報の窃取、ログの改ざんの有無を確認します。

## 恒久対策

- polkit、sudo、および OS 全体を最新の状態に維持する
- sudo 権限を付与するアカウントを最小限に限定し、`NOPASSWD` の使用を避ける
- auditd による setuid 実行および `execve` の監査を有効化する
- ログをホスト外に転送し、改ざん不能な複製を保持する
