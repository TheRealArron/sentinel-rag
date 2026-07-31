---
id: sample-ja-ssh-bruteforce
title: "SSHサーバに対するブルートフォース攻撃の増加に関する注意喚起"
publisher: "JPCERT/CC 形式のサンプル文書（実在の公開文書ではありません）"
published: 2026-03-18
lang: ja
severity: high
mitre: [T1110.001, T1110.003, T1078.003]
keywords:
  - ブルートフォース
  - brute force
  - パスワードスプレー
  - password spraying
  - 認証失敗
  - failed password
  - 総当たり攻撃
  - sshd
  - 不正アクセス
  - unauthorized access
  - fail2ban
---

## 概要

インターネットに公開された SSH サーバ（TCP 22 番ポート）に対する、辞書攻撃および
総当たり攻撃（ブルートフォース攻撃）の観測件数が継続的に増加しています。特に、
一般的なユーザー名（`admin`、`root`、`oracle`、`test`、`ubuntu`、`pi`、`postgres` 等）
を用いた自動化された攻撃が大半を占めており、家庭内サーバや小規模事業者のサーバが
無差別に標的となっています。

本注意喚起では、攻撃の検知方法と、攻撃が成功した場合の対応手順について説明します。

## 攻撃の特徴

観測されている攻撃には、次の二つの類型があります。

**1. 無差別型（機会的攻撃）**
ボットネットによる広範なスキャンの一部として実施されます。一つの送信元から
3〜4 個の認証情報を試行し、失敗すると次のホストへ移動します。日常的な「背景雑音」
であり、単独では緊急性は低いと評価できます。

**2. 標的型（継続的攻撃）**
同一の送信元 IP アドレスから、短時間に多数の認証試行が行われます。60 秒以内に
5 回以上の認証失敗が発生している場合は、機会的攻撃ではなく継続的な攻撃campaignと
判断してください。複数のユーザー名に対して試行されている場合（パスワード
スプレー）は、攻撃者が有効なアカウント名を把握していない段階であることを示す
一方で、認証情報リストを保有している可能性も示唆します。

## ログ上の痕跡

Ubuntu 系ディストリビューションでは `/var/log/auth.log`、および journald の
`ssh` ユニットに記録されます。

```
sshd[4001]: Failed password for invalid user admin from 203.0.113.45 port 51001 ssh2
sshd[4002]: Invalid user oracle from 203.0.113.45 port 51002
sshd[4004]: Failed password for root from 203.0.113.45 port 51004 ssh2
sshd[4021]: error: maximum authentication attempts exceeded for root from 203.0.113.45
sshd[4006]: Accepted password for arron from 203.0.113.45 port 51006 ssh2
```

`invalid user` を含む行は、存在しないアカウントに対する試行であり、攻撃者が
ユーザー名の列挙を行っていることを意味します。

## 最も重要な判断基準

**認証失敗の連続の直後に、同一送信元からの認証成功が記録されている場合は、
侵害が成立したものとして扱ってください。**

攻撃が停止したのは、攻撃が成功したためです。この状態は単なる「ログイン成功」
ではなく、アカウント侵害（MITRE ATT&CK: T1078.003）への移行を示す最も重要な
シグナルです。直ちに以下の調査を実施してください。

```bash
sudo last -F | head -40
sudo lastlog
sudo ss -tanp
sudo find /home /root -name authorized_keys -newermt '-2 days' -ls
sudo journalctl -u ssh --since '-24 hours' | grep -E 'Accepted|Failed'
```

また、送信元 IP アドレスがグローバルアドレスである場合は、プライベート
アドレスからの試行より高いリスクとして評価してください。プライベート
アドレスからの認証失敗は、多くの場合バックアップジョブの設定誤りや
スクリプト内の古い認証情報が原因です。

## 対策

### 恒久対策（推奨）

1. **パスワード認証の無効化**
   `/etc/ssh/sshd_config` において以下を設定し、公開鍵認証のみを許可します。
   これにより本攻撃手法そのものが成立しなくなります。

   ```
   PasswordAuthentication no
   KbdInteractiveAuthentication no
   PermitRootLogin no
   MaxAuthTries 3
   ```

   設定後、`sudo systemctl reload ssh` を実行してください。

2. **公開範囲の限定**
   VPN 経由でのみ SSH を許可する、または UFW により接続元を制限します。

   ```bash
   sudo ufw limit from 203.0.113.0/24 to any port 22 proto tcp
   ```

### 緩和策

3. **接続レート制限の導入**
   `sudo apt-get install fail2ban` を実行し、`sshd` jail を有効化します。
   既定設定（`maxretry 5`、`bantime 10m`）でも自動化された攻撃の大半を
   遮断できます。

4. **攻撃元アドレスの遮断**
   `sudo ufw insert 1 deny from <送信元IP> to any`

   なお、遮断ルールを追加する際は、許可ルールより前に挿入する必要があります。
   既存の許可ルールの後に追加した場合、遮断ルールは評価されません。

### 推奨しない対策

SSH のポート番号の変更は、無差別スキャンによるログ量を減らす効果はありますが、
ポートスキャンを行う攻撃者に対する防御効果はありません。恒久対策の代替には
なりません。

## 侵害が確認された場合

当該アカウントの認証情報および SSH 鍵をすべて更新し、永続化手口
（`authorized_keys` の改変、systemd ユニットの追加、cron エントリの追加、
新規アカウントの作成）の有無を確認したうえで、インシデントの終息を判断して
ください。ログの改ざんが行われている可能性があるため、ホスト外に転送された
ログとの照合を推奨します。
