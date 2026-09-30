#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把本机 WorkBuddy 登录态同步到 GitHub 仓库 Secrets（一键配置 / 续期）。

用途：
  - 首次配置：把本机凭据写入 GitHub Secrets，供 Actions 使用
  - 续期：凭据失效后重新执行本脚本即可覆盖更新

关键变更（适配客户端 5.6.2+）
-----------------------------
5.6.2 起登录态里的 accessToken / refreshToken 变成 AES-256-GCM 信封
    {"$wbEncrypted":1,"envelope":"..."}
解密密钥不落盘、只由运行中的客户端在内存中提供 —— 云端 runner 拿不到。
旧版脚本会把这一整坨 JSON 当成 token 写进 Secret，Actions 必然鉴权失败。

本版因此：
  1) 自动识别「明文 / 加密信封」两种登录态；
  2) **优先取长效令牌并写入 Secret `WB_REFRESH_TOKEN`** —— 它在云端可自行换取
     新的接口令牌，约 60 天有效，是 GitHub Actions 场景的正解；
  3) 遇到加密信封且本机无法解密时，明确给出可执行路径，
     **绝不把信封 JSON 写进 Secret**（旧版最大的坑）。

  解密能力复用本机已安装的 WorkBuddy签到助手 skill（若存在）；未安装时会直接
  告诉你该装什么、该跑哪条命令。

依赖：
  - 本机已安装并登录 WorkBuddy 客户端（提供登录态文件）
  - （推荐）已安装 GitHub CLI（gh）并执行过 gh auth login；未装则降级为手动指引
    https://cli.github.com/

用法：
  python scripts/sync_token_to_github.py                      # 自动识别当前仓库
  python scripts/sync_token_to_github.py --repo owner/repo
  python scripts/sync_token_to_github.py --dry-run            # 只预览，不真正写入

  # 顺带写入通知通道（可选，留空则不动）
  python scripts/sync_token_to_github.py --wecom "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx"
  python scripts/sync_token_to_github.py --pushplus "你的token"
  python scripts/sync_token_to_github.py --bark "https://api.day.app/你的KEY/"
  python scripts/sync_token_to_github.py --serverchan "SCTxxxxx"
  python scripts/sync_token_to_github.py --success-notify

安全说明：
  - 只读取本机登录态文件，不修改、不上传到除 GitHub Secrets 之外的任何地方
  - 全程不打印真实 token，也不打印 token 长度 / 片段
  - 通过 stdin 传值给 gh，避免密钥出现在进程命令行参数中
  - 未安装 gh 时自动降级为「手动配置指引」，不会卡住，也不会泄露凭据
"""

import argparse
import glob
import importlib
import json
import os
import shutil
import subprocess
import sys

AUTH_CANDIDATES_WIN = [
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info"),
    os.path.join(os.environ.get("APPDATA", ""), "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info"),
]

# 本机可能提供 5.6.2+ 信封解密能力的模块所在目录（按优先级）
SKILL_DIRS = [
    os.path.join(os.path.expanduser("~"), ".workbuddy", "skills",
                 "totorosir-workbuddy-checkin", "scripts"),
    os.path.join(os.path.expanduser("~"), ".workbuddy", "scripts"),
]

EKEY_HINT = (
    "本机登录态是 5.6.2+ 的加密形态（AES-256-GCM 信封），密钥不在文件里、\n"
    "  只由运行中的客户端在内存中提供。请三选一取得**明文**长效令牌：\n"
    "    ① 已安装「WorkBuddy签到助手」skill 时（推荐，最省事）：\n"
    "         python \"%s/rt_auth.py\" --export-rt\n"
    "       把输出的整段字符串填进 Secret WB_REFRESH_TOKEN。\n"
    "    ② 设好环境变量 WORKBUDDY_ATREST_KEY（44 字符密钥）后重跑本脚本，自动解密。\n"
    "    ③ 用「WorkBuddy自动签到分享包」在本机导出令牌后手动填入。\n"
    "  提示：客户端需处于已登录状态；解密时脚本与客户端要在同一个 Windows 用户下运行。"
)


def find_auth_file():
    home = os.path.expanduser("~")
    cands = list(AUTH_CANDIDATES_WIN)
    if sys.platform == "darwin":
        cands.append(os.path.join(home, "Library", "Application Support", "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info"))
    else:
        cands.append(os.path.join(home, ".config", "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info"))
    cands.append(os.path.join(home, ".workbuddy", "auth", "workbuddy-desktop.info"))
    for p in cands:
        if p and os.path.isfile(p):
            return p
    return None


def _decryptor():
    """尝试加载提供 decrypt_access_token_field 的模块（本机签到 skill）。

    返回 (module, 目录)；找不到返回 (None, None)。
    本仓库**不自带**解密实现 —— 该能力需要读取客户端进程内存中的密钥，
    不适合随公开仓库分发；因此这里只做「本机已有则复用」的软依赖。
    """
    for d in SKILL_DIRS:
        if not os.path.isfile(os.path.join(d, "workbuddy_checkin.py")):
            continue
        if d not in sys.path:
            sys.path.insert(0, d)
        try:
            m = importlib.import_module("workbuddy_checkin")
            if hasattr(m, "decrypt_access_token_field"):
                return m, d
        except Exception:
            continue
    return None, None


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


def load_credential(path):
    """读取登录态，返回 (refresh_token, access_token, domain, notes)。

    两个 token 都可能为 None（加密且无法解密时）。
    """
    with open(path, "r", encoding="utf-8") as f:
        auth = json.load(f).get("auth", {})
    mod, mod_dir = _decryptor()
    rt, rt_note = _resolve_field(auth.get("refreshToken"), mod, "refreshToken")
    at, at_note = _resolve_field(auth.get("accessToken"), mod, "accessToken")
    domain = auth.get("domain") or "www.codebuddy.cn"
    notes = {"refreshToken": rt_note, "accessToken": at_note, "decryptor": mod_dir}
    return rt, at, domain, notes


def mask(t):
    """只报存在性与长度，不报任何字符片段（与签到主脚本口径一致）。"""
    if not t:
        return "<空>"
    return "<已配置，长度 %d，不回显片段>" % len(t)


def gh_available():
    """检测 gh 是否可用：先 PATH，再探测常见安装位置。"""
    if shutil.which("gh"):
        return True
    home = os.path.expanduser("~")
    candidates = [
        r"C:\Program Files\GitHub CLI\gh.exe",
        r"C:\Program Files (x86)\GitHub CLI\gh.exe",
        os.path.join(home, "AppData", "Local", "GitHubCLI", "gh.exe"),
        os.path.join(home, "AppData", "Local", "Programs", "GitHub CLI", "gh.exe"),
    ]
    return any(os.path.isfile(c) for c in candidates)


def gh_set_secret(repo, name, value, dry_run=False):
    """通过 stdin 写入 Secret，避免密钥出现在命令行参数中。

    安全要点：
      - 值经 stdin 传递，不出现在进程列表（ps）里
      - 输出只提示「已写入 Secret：<名称>」，绝不回显值或长度
    """
    cmd = ["gh", "secret", "set", name]
    if repo:
        cmd += ["--repo", repo]
    if dry_run:
        print("  [dry-run] 将写入 Secret：%s" % name)
        return True
    try:
        r = subprocess.run(cmd, input=value.encode("utf-8"),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            err = r.stderr.decode("utf-8", "replace").strip()
            print("  ✗ 写入 %s 失败：%s" % (name, err))
            return False
        print("  ✓ 已写入 Secret：%s" % name)
        return True
    except FileNotFoundError:
        print("  ✗ 未找到 gh 命令，请先安装 GitHub CLI：https://cli.github.com/")
        return False
    except Exception as e:
        print("  ✗ 写入 %s 异常：%s" % (name, e))
        return False


def find_git():
    """定位 git 可执行文件：优先 PATH，其次常见安装位置 / WorkBuddy 自带 PortableGit。

    为什么需要它：某些环境下 PATH 异常（如 WorkBuddy 内置 Bash 的 PATH 缺失），
    直接调用 "git" 会 FileNotFoundError，这里做主动探测以提升健壮性。
    """
    found = shutil.which("git")
    if found:
        return found
    home = os.path.expanduser("~")
    candidates = [
        r"C:\Program Files\Git\cmd\git.exe",
        r"C:\Program Files (x86)\Git\cmd\git.exe",
        os.path.join(home, "AppData", "Local", "Programs", "Git", "cmd", "git.exe"),
    ]
    # WorkBuddy 自带 PortableGit（版本号不确定，做通配搜索）
    candidates += sorted(glob.glob(os.path.join(
        home, ".workbuddy", "binaries", "PortableGit", "versions", "*", "cmd", "git.exe")))
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def detect_repo(git_path=None):
    """尝试从当前目录的 git remote 推断仓库（owner/repo）。"""
    git_exe = git_path or find_git() or "git"
    try:
        r = subprocess.run([git_exe, "remote", "get-url", "origin"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            return None
        url = r.stdout.decode("utf-8", "replace").strip()
        # git@github.com:owner/repo.git 或 https://github.com/owner/repo.git
        if "github.com" not in url:
            return None
        part = url.split("github.com")[-1].lstrip(":/").rstrip("/")
        if part.endswith(".git"):
            part = part[:-4]
        return part
    except Exception:
        return None


def print_manual_guide(secret_name, domain, repo, channels, use_rt):
    """gh 不可用时的降级方案：打印手动配置指引（不含凭据明文）。"""
    print()
    print("=" * 60)
    print("⚠️  未检测到 GitHub CLI（gh），无法自动写入 Secrets。")
    print("    请在浏览器中按以下步骤手动配置（共 %d 项）：" % (1 + len(channels)))
    print("=" * 60)
    print()
    print("打开：仓库 → Settings → Secrets and variables → Actions → New repository secret")
    if repo:
        print("仓库地址：https://github.com/%s/settings/secrets/actions" % repo)
    print()
    print("需要添加的 Secret（名称 → 值来源）：")
    print("  1) %s" % secret_name)
    if use_rt:
        print("     → 值为你的**长效令牌**（明文）；可运行下面的命令复制到剪贴板（不会打印到屏幕）：")
    else:
        print("     → 值为你的**接口令牌**（明文）；可运行下面的命令复制到剪贴板（不会打印到屏幕）：")
    print()
    if sys.platform.startswith("win"):
        print("       python scripts/copy_token_to_clipboard.py")
    else:
        print("       python scripts/copy_token_to_clipboard.py   # 需自行安装剪贴板工具，或手动打开登录态文件复制")
    print()
    for i, (name, _) in enumerate(channels, start=2):
        print("  %d) %s" % (i, name))
    print()
    print("接口域名（供参考，已内置默认值 www.codebuddy.cn）：%s" % domain)
    print()
    print("另外建议安装 gh 以获得更好的体验：https://cli.github.com/")
    print("安装后重新运行本脚本即可自动完成。")
    print()
    print("提示：也可直接打开登录态文件复制对应字段（仅在本人设备上操作）：")
    print("  %s" % find_auth_file())
    print("  ⚠️ 若该文件里的值是 {\"$wbEncrypted\":1,...} 形态，不要直接复制 —— 那是加密信封，")
    print("     云端无法解密，粘贴进 Secret 只会得到鉴权失败。")


def main():
    ap = argparse.ArgumentParser(description="把本机 WorkBuddy 登录态同步到 GitHub Secrets")
    ap.add_argument("--repo", help="目标仓库 owner/repo（默认自动从 git remote 推断）")
    ap.add_argument("--wecom", help="企业微信群机器人 webhook（可选）")
    ap.add_argument("--pushplus", help="PushPlus token（可选）")
    ap.add_argument("--bark", help="Bark URL（可选）")
    ap.add_argument("--serverchan", help="Server酱（方糖）SendKey（可选）")
    ap.add_argument("--success-notify", action="store_true", help="签到成功也推送播报")
    ap.add_argument("--dry-run", action="store_true", help="只预览，不真正写入")
    args = ap.parse_args()

    print("=" * 60)
    print("WorkBuddy 登录态 → GitHub Secrets 同步工具")
    print("=" * 60)

    has_gh = gh_available() or args.dry_run

    repo = args.repo or detect_repo()
    if repo:
        print("目标仓库：%s" % repo)
    else:
        print("未指定仓库且无法自动推断（可能未配置 git remote）；可用 --repo owner/repo 指定")

    auth_path = find_auth_file()
    if not auth_path:
        print("✗ 未找到本机登录态文件，请先登录 WorkBuddy 客户端")
        sys.exit(1)
    print("登录态文件：%s" % auth_path)

    rt, at, domain, notes = load_credential(auth_path)
    print("字段状态：")
    print("  refreshToken（长效令牌）：%s" % notes["refreshToken"])
    print("  accessToken （短效令牌）：%s" % notes["accessToken"])
    if notes["decryptor"]:
        print("  解密能力：已复用本机模块（%s）" % notes["decryptor"])
    else:
        print("  解密能力：未找到（加密登录态无法在本脚本内解密）")
    print("接口域名：%s" % domain)
    print("-" * 60)

    # 决定写哪个凭据 Secret：长效令牌优先
    if rt:
        secret_name, secret_value, use_rt = "WB_REFRESH_TOKEN", rt, True
    elif at:
        secret_name, secret_value, use_rt = "WB_ACCESS_TOKEN", at, False
    else:
        print("✗ 无法取得任何明文凭据（登录态可能是 5.6.2+ 加密形态且本机无法解密）。")
        print()
        skill_dir = os.path.join(os.path.expanduser("~"), ".workbuddy", "skills",
                                 "totorosir-workbuddy-checkin", "scripts")
        print(EKEY_HINT % skill_dir)
        if not has_gh:
            print()
            print_manual_guide("WB_REFRESH_TOKEN", domain, repo, [], True)
        sys.exit(1)

    # gh 不可用（且非 dry-run）→ 降级为手动配置指引，不在中途失败
    if not has_gh:
        channels = []
        if args.wecom:
            channels.append(("WECOM_WEBHOOK", args.wecom))
        if args.pushplus:
            channels.append(("PUSHPLUS_TOKEN", args.pushplus))
        if args.bark:
            channels.append(("BARK_URL", args.bark))
        if args.serverchan:
            channels.append(("SERVERCHAN_SENDKEY", args.serverchan))
        if args.success_notify:
            channels.append(("SUCCESS_NOTIFY", "true"))
        print_manual_guide(secret_name, domain, repo, channels, use_rt)
        sys.exit(0)

    ok = True
    if use_rt:
        print("[1/3] 写入长效令牌与域名（推荐通道）")
    else:
        print("[1/3] 写入接口令牌与域名（兼容通道；请确认客户端为 5.5.x 及更早）")
    ok &= gh_set_secret(repo, secret_name, secret_value, args.dry_run)
    ok &= gh_set_secret(repo, "WB_DOMAIN", domain, args.dry_run)

    print("[2/3] 写入通知通道（仅填写了的）")
    any_channel = False
    if args.wecom:
        ok &= gh_set_secret(repo, "WECOM_WEBHOOK", args.wecom, args.dry_run); any_channel = True
    if args.pushplus:
        ok &= gh_set_secret(repo, "PUSHPLUS_TOKEN", args.pushplus, args.dry_run); any_channel = True
    if args.bark:
        ok &= gh_set_secret(repo, "BARK_URL", args.bark, args.dry_run); any_channel = True
    if args.serverchan:
        ok &= gh_set_secret(repo, "SERVERCHAN_SENDKEY", args.serverchan, args.dry_run); any_channel = True
    if args.success_notify:
        ok &= gh_set_secret(repo, "SUCCESS_NOTIFY", "true", args.dry_run); any_channel = True
    if not any_channel:
        print("  （未指定任何通知通道，跳过；仅失败时也不会推送）")

    print("[3/3] 完成")
    print("-" * 60)
    if ok:
        print("✓ 同步成功。")
        print("  下一步：在 GitHub 仓库 Actions 页面选中「WorkBuddy 每日自动签到」")
        print("         点击 Run workflow 手动跑一次，确认结果为 status=ok。")
    else:
        print("✗ 部分 Secret 写入失败，请检查 gh 登录状态与仓库权限（需 repo 写权限）。")
        sys.exit(1)


if __name__ == "__main__":
    main()
