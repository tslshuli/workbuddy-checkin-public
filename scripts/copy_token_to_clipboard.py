#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把本机 WorkBuddy 登录态里的凭据复制到剪贴板（用于手动粘贴到 GitHub Secrets）。

为什么需要它：
  未安装 GitHub CLI（gh）时，用户需手动到网页添加 Secret，但令牌很长，
  肉眼选中复制极易漏字符，且直接打印到终端会留存在滚动历史 / 日志中。
  本脚本通过剪贴板传递，不打印内容。

适配客户端 5.6.2+
------------------
登录态里的 accessToken / refreshToken 可能是 AES-256-GCM 加密信封
    {"$wbEncrypted":1,"envelope":"..."}
**信封不能直接粘贴进 Secret**（云端拿不到解密密钥，必然鉴权失败）。
本脚本会自动识别：能解密则复制明文长效令牌，不能解密则明确告诉你该怎么办。

安全说明：
  - 不打印 token 内容（仅提示已复制，并用脱敏形态核对类型）
  - 只读登录态文件，不修改、不联网
  - 用完请自行清空剪贴板（脚本会提示）

用法：
  python scripts/copy_token_to_clipboard.py                  # 复制长效令牌（推荐）
  python scripts/copy_token_to_clipboard.py --access-token   # 复制短效接口令牌
  python scripts/copy_token_to_clipboard.py --domain         # 复制接口域名
"""

import argparse
import importlib
import json
import os
import subprocess
import sys

# 本机可能提供 5.6.2+ 信封解密能力的模块所在目录（按优先级）
SKILL_DIRS = [
    os.path.join(os.path.expanduser("~"), ".workbuddy", "skills",
                 "totorosir-workbuddy-checkin", "scripts"),
    os.path.join(os.path.expanduser("~"), ".workbuddy", "scripts"),
]


def find_auth_file():
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
    cands.append(os.path.join(home, ".workbuddy", "auth", "workbuddy-desktop.info"))
    for p in cands:
        if p and os.path.isfile(p):
            return p
    return None


def _decryptor():
    """尝试加载提供 decrypt_access_token_field 的模块（本机签到 skill）。"""
    for d in SKILL_DIRS:
        if not os.path.isfile(os.path.join(d, "workbuddy_checkin.py")):
            continue
        if d not in sys.path:
            sys.path.insert(0, d)
        try:
            m = importlib.import_module("workbuddy_checkin")
            if hasattr(m, "decrypt_access_token_field"):
                return m
        except Exception:
            continue
    return None


def _resolve_field(raw, mod, label):
    """把登录态里的原始字段解成明文。返回 (明文|None, 说明)。"""
    if raw is None:
        return None, "%s 字段不存在" % label
    if isinstance(raw, str):
        if not raw.strip():
            return None, "%s 为空" % label
        return raw.strip(), "%s：明文" % label
    if isinstance(raw, dict) and raw.get("$wbEncrypted") == 1:
        if mod is None:
            return None, "%s：加密信封（本机未找到可用的解密实现）" % label
        try:
            return mod.decrypt_access_token_field(raw), "%s：加密信封（已解密）" % label
        except Exception as e:
            return None, "%s：加密信封（解密失败：%s）" % (label, str(e)[:160])
    return None, "%s：形态无法识别" % label


def mask(t):
    """脱敏回显：只给长度，不给片段。"""
    if not t:
        return "<空>"
    return "<已配置，长度 %d，不回显片段>" % len(t)


def copy_to_clipboard(text):
    """跨平台写入剪贴板；成功返回 True。不依赖第三方库。"""
    try:
        if sys.platform.startswith("win"):
            # 通过 PowerShell 写入剪贴板（Set-Clipboard 在 Win10+ 可用）
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 "Set-Clipboard -Value ([Console]::In.ReadToEnd())"],
                input=text.encode("utf-8"),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            return r.returncode == 0
        elif sys.platform == "darwin":
            r = subprocess.run(["pbcopy"], input=text.encode("utf-8"),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            return r.returncode == 0
        else:
            # Linux: 依次尝试 xclip / xsel / wl-copy
            for cmd in (["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"], ["wl-copy"]):
                try:
                    r = subprocess.run(cmd, input=text.encode("utf-8"),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                    if r.returncode == 0:
                        return True
                except FileNotFoundError:
                    continue
            return False
    except Exception:
        return False


def _print_envelope_hint():
    skill_dir = os.path.join(os.path.expanduser("~"), ".workbuddy", "skills",
                             "totorosir-workbuddy-checkin", "scripts")
    print()
    print("本机登录态是 5.6.2+ 的加密形态（AES-256-GCM 信封），密钥不在文件里、")
    print("只由运行中的客户端在内存中提供 —— 云端 runner 无法解密，**不能直接粘贴进 Secret**。")
    print("请三选一取得**明文**长效令牌：")
    print("  ① 已安装「WorkBuddy签到助手」skill 时（推荐，最省事）：")
    print("       python \"%s/rt_auth.py\" --export-rt" % skill_dir)
    print("     把输出的整段字符串填进 Secret WB_REFRESH_TOKEN。")
    print("  ② 设好环境变量 WORKBUDDY_ATREST_KEY（44 字符密钥）后重跑本脚本，自动解密。")
    print("  ③ 用「WorkBuddy自动签到分享包」在本机导出令牌后手动填入。")
    print("提示：客户端需处于已登录状态；解密时脚本与客户端要在同一个 Windows 用户下运行。")


def main():
    ap = argparse.ArgumentParser(
        description="复制长效令牌 / 接口令牌 / 域名到剪贴板（用于手动配置 GitHub Secrets）")
    ap.add_argument("--domain", action="store_true", help="复制接口域名而非令牌")
    ap.add_argument("--access-token", action="store_true",
                    help="复制短效接口令牌（默认复制长效令牌，5.6.2+ 推荐）")
    args = ap.parse_args()

    path = find_auth_file()
    if not path:
        print("✗ 未找到本机登录态文件，请先登录 WorkBuddy 客户端")
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as f:
        auth = json.load(f).get("auth", {})

    domain = auth.get("domain") or "www.codebuddy.cn"

    if args.domain:
        if copy_to_clipboard(domain):
            print("✓ 已复制接口域名到剪贴板：%s" % domain)
            print("  → 粘贴到 Secret「WB_DOMAIN」")
        else:
            print("✗ 复制失败，请手动填写：%s" % domain)
        return

    if args.access_token:
        field, secret_name, label = "accessToken", "WB_ACCESS_TOKEN", "短效接口令牌"
    else:
        field, secret_name, label = "refreshToken", "WB_REFRESH_TOKEN", "长效令牌"

    value, note = _resolve_field(auth.get(field), _decryptor(), field)
    print("字段状态：%s" % note)

    if not value:
        # 不复制任何东西到剪贴板 —— 避免用户误把信封粘进 Secret
        _print_envelope_hint()
        sys.exit(1)

    if copy_to_clipboard(value):
        print("✓ 已复制%s到剪贴板（脱敏核对：%s）" % (label, mask(value)))
        print("  → 粘贴到 Secret「%s」" % secret_name)
        print()
        print("⚠️ 安全提醒：配置完成后请清空剪贴板，避免凭据残留。")
        print("   清空方法（Windows）：复制一段无关文本即可覆盖。")
    else:
        print("✗ 复制到剪贴板失败（可能缺少剪贴板工具或权限）。")
        print("  备选方案：手动打开下面的文件，复制其中 auth.%s 的值：" % field)
        print("  %s" % path)
        sys.exit(1)


if __name__ == "__main__":
    main()
