#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
部署前安全自检：扫描本项目是否存在凭据泄露、危险代码、敏感文件。

在推送到 GitHub 之前运行，确保不会有任何凭据随代码泄露。

用法：
  python security_audit.py              # 审计当前目录（脚本所在目录 = 项目根）
  python security_audit.py --path .     # 指定项目根目录

检查项：
  1. 硬编码凭据（JWT / 企微 webhook / Bark key / 私钥 / 云厂商密钥 / GitHub PAT）
  2. 本机真实 token 是否出现在任何交付文件中（最强校验）
  3. 登录态加密信封（$wbEncrypted）是否被误提交 —— 客户端 5.6.2+ 新增
  4. 危险代码模式（shell=True / eval / os.system / rm -rf / verify=False / curl|sh）
  5. 敏感文件是否误入项目（notify_config.json / workbuddy-desktop.info 等）
  6. .gitignore 是否覆盖关键项
  7. workflow 安全实践（最小权限 / 无 pull_request_target / 退出码传播等）

退出码：0 = 无风险；1 = 发现风险（可用于 CI 卡点）
"""

import argparse
import json
import os
import re
import sys

SECRET_PATTERNS = {
    "JWT 格式 token": re.compile(r"eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}"),
    "企微 webhook": re.compile(r"qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[A-Za-z0-9\-]{8,}"),
    "Bark key": re.compile(r"api\.day\.app/[A-Za-z0-9]{20,}"),
    "私钥块": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "AWS AK": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub PAT": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    "Slack token": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
}

DANGER_PATTERNS = {
    "shell=True": re.compile(r"shell\s*=\s*True"),
    "eval/exec": re.compile(r"\b(eval|exec)\s*\("),
    "os.system": re.compile(r"os\.system\s*\("),
    "rm -rf": re.compile(r"rm\s+-rf"),
    "verify=False": re.compile(r"verify\s*=\s*False"),
    "curl 管道执行": re.compile(r"curl\s+[^|]*\|\s*(ba)?sh"),
}

# 登录态密文特征：一旦出现在仓库文件里，说明把本机登录态内容粘进来了。
# 即便它不是「可用的」明文凭据，也绝不该出现在交付物中（且容易诱导用户误用）。
# ⚠️ 只匹配「带真实 base64 载荷」的完整信封 —— 文档里描述格式用的
#    {"$wbEncrypted":1,"envelope":"<base64>"} 这类示意写法不会被误报。
ENVELOPE_RX = re.compile(
    r'\$wbEncrypted["\']?\s*:\s*1\s*,\s*["\']?envelope["\']?\s*:\s*["\'][A-Za-z0-9+/=]{40,}')

SECRET_FILENAMES = {"notify_config.json", "workbuddy-desktop.info", "checkin-rt.json"}
SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", "node_modules"}
# 自检脚本自身的检测规则字面量、以及审计报告中对危险模式的文字引用，
# 都会命中模式匹配（误报），故一并跳过
SKIP_FILES = {"security_audit.py", "SECURITY-AUDIT.md"}


def find_local_token():
    """尝试读取本机 WorkBuddy 登录态 token，用于最强校验。读取失败返回 None。

    注意：客户端 5.6.2+ 起 auth.accessToken 是 AES-256-GCM 信封（dict），
    不是可参与字符串比对的明文 —— 此时返回 None（跳过比对），
    否则 `real_token in txt` 会因类型不符而抛异常。
    """
    home = os.path.expanduser("~")
    cands = []
    if sys.platform.startswith("win"):
        for env in ("LOCALAPPDATA", "APPDATA"):
            base = os.environ.get(env, "")
            if base:
                cands.append(os.path.join(base, "CodeBuddyExtension", "Data",
                                          "Public", "auth", "workbuddy-desktop.info"))
    elif sys.platform == "darwin":
        cands.append(os.path.join(home, "Library", "Application Support",
                                  "CodeBuddyExtension", "Data", "Public", "auth",
                                  "workbuddy-desktop.info"))
    else:
        cands.append(os.path.join(home, ".config", "CodeBuddyExtension", "Data",
                                  "Public", "auth", "workbuddy-desktop.info"))
    for p in cands:
        try:
            if os.path.isfile(p):
                with open(p, encoding="utf-8") as f:
                    tok = json.load(f).get("auth", {}).get("accessToken")
                if isinstance(tok, str) and tok.strip():
                    return tok
        except Exception:
            continue
    return None


def main():
    ap = argparse.ArgumentParser(description="部署前安全自检")
    ap.add_argument("--path", default=os.path.dirname(os.path.abspath(__file__)),
                    help="项目根目录（默认脚本所在目录）")
    args = ap.parse_args()

    base = os.path.abspath(args.path)
    if not os.path.isdir(base):
        print("✗ 目录不存在：%s" % base)
        sys.exit(1)

    real_token = find_local_token()

    print("=" * 70)
    print("部署前安全自检")
    print("=" * 70)
    print("审计目录：%s" % base)
    print("本机 token 校验：%s" % ("已载入（用于比对）" if real_token else "无法读取（跳过比对）"))
    print()

    leaks, dangers, secret_files, files = [], [], [], []

    for dp, dn, fn in os.walk(base):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, base)
            files.append(rel)

            if f in SECRET_FILENAMES:
                secret_files.append(rel)

            # 跳过自检脚本本身（其正则模式字面量会造成误报）
            if f in SKIP_FILES:
                continue

            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    txt = fh.read()
            except Exception:
                continue

            if real_token:
                if real_token in txt:
                    leaks.append((rel, "!! 完整真实 token 明文 !!", "<REDACTED>"))
                elif real_token[:50] in txt:
                    leaks.append((rel, "!! 真实 token 长片段 !!", "<REDACTED>"))
                elif real_token[-30:] in txt:
                    leaks.append((rel, "! 真实 token 尾部片段 !", "<REDACTED>"))

            if ENVELOPE_RX.search(txt):
                leaks.append((rel, "!! 登录态加密信封（$wbEncrypted）!!",
                              "不可用于云端，请删除"))

            for name, rx in SECRET_PATTERNS.items():
                if rx.search(txt):
                    leaks.append((rel, name, "<见文件>"))

            for name, rx in DANGER_PATTERNS.items():
                m = rx.search(txt)
                if m:
                    ln = txt[:m.start()].count("\n") + 1
                    dangers.append((rel, name, "L%d" % ln))

    print("[1] 文件清单（%d 个）" % len(files))
    for f in sorted(files):
        print("    " + f)
    print()

    print("[2] 凭据泄露扫描")
    if leaks:
        for r, n, s in leaks:
            print("    [严重] %-38s %-26s %s" % (r, n, s))
    else:
        print("    [通过] 未发现任何真实凭据 / 密钥 / token 明文 / 登录态信封")
    print()

    print("[3] 危险代码模式")
    if dangers:
        for r, n, s in dangers:
            print("    [注意] %-38s %-16s %s" % (r, n, s))
    else:
        print("    [通过] 未发现 shell=True / eval / os.system / rm -rf / verify=False 等")
    print()

    print("[4] 敏感文件误入库")
    if secret_files:
        for f in secret_files:
            print("    [严重] 发现含密钥的文件：%s" % f)
    else:
        print("    [通过] 未发现 notify_config.json / workbuddy-desktop.info 等敏感文件")
    print()

    gi = os.path.join(base, ".gitignore")
    print("[5] .gitignore 覆盖")
    if os.path.isfile(gi):
        with open(gi, encoding="utf-8") as fh:
            g = fh.read()
        for m in ("notify_config.json", "checkin.log", "__pycache__", "result.json",
                  "workbuddy-desktop.info"):
            print("    %s %s" % ("[通过]" if m in g else "[缺失]", m))
    else:
        print("    [严重] 缺少 .gitignore")
    print()

    # 6) workflow 安全实践
    wf = os.path.join(base, ".github", "workflows", "checkin.yml")
    if os.path.isfile(wf):
        with open(wf, encoding="utf-8") as fh:
            w = fh.read()
        print("[6] workflow 安全实践")
        for label, cond in [
            ("使用 Secrets 注入凭据",
             any(x in w for x in ("secrets.WB_REFRESH_TOKEN", "secrets.WB_ACCESS_TOKEN",
                                  "secrets.WORKBUDDY_ACCESS_TOKEN"))),
            ("无 pull_request_target（防投毒）", "pull_request_target" not in w),
            ("声明最小权限 permissions", "permissions:" in w),
            ("固定 concurrency 防重复", "concurrency:" in w),
            ("有 timeout-minutes", "timeout-minutes:" in w),
            ("用 PIPESTATUS 传播退出码", "PIPESTATUS" in w),
            ("摘要经白名单过滤", "summarize_result.py" in w),
            ("未直接 cat 原始结果进摘要", "cat result.json" not in w),
            ("未打印 token 长度", all(x not in w for x in (
                "${#WORKBUDDY_ACCESS_TOKEN}", "${#WB_REFRESH_TOKEN}", "${#WB_ACCESS_TOKEN}"))),
            ("未出现 curl|sh 远程执行", "curl" not in w),
        ]:
            print("    %s %s" % ("[通过]" if cond else "[注意]", label))
        print()

    print("=" * 70)
    risk = bool(leaks or secret_files)
    print("结论：泄露风险 %s ｜ 危险代码 %s ｜ 敏感文件 %s" % (
        "有" if leaks else "无", "有" if dangers else "无", "有" if secret_files else "无"))
    if risk:
        print("⚠️ 请修复上述 [严重] 项后再推送到公开仓库！")
    else:
        print("✓ 未发现泄密风险，可安全推送（仍需自行确认仓库可见性与平台规则风险）。")
    print("=" * 70)
    sys.exit(1 if risk else 0)


if __name__ == "__main__":
    main()
