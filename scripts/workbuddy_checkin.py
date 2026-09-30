#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WorkBuddy签到助手（每日自动签到脚本，接口直签，无需 GUI 点击 / OCR）

v2.1.0-ci 关键变更（适配 WorkBuddy 客户端 5.6.2+）
==================================================
客户端 5.6.2 起对登录态做静态加密（AtRestEncryption）：workbuddy-desktop.info 里的
auth.accessToken / auth.refreshToken 不再是明文 JWT，而是 AES-256-GCM 信封
    {"$wbEncrypted": 1, "envelope": "<base64>"}
解密密钥不落盘、只由运行中的客户端在内存中提供 —— 云端 runner 拿不到。
=> 旧做法「把本机 accessToken 原样塞进 Secret」在新版上必然鉴权失败。

本版因此引入**双凭据通道**，并优先走长效令牌：

  通道 R（推荐；5.6.2+ 必用）· Secret WB_REFRESH_TOKEN
      长效令牌（refresh token，约 60 天有效）→ 每次运行先向插件网关
      copilot.tencent.com/v2/plugin/auth/token/refresh 换取新的接口令牌 → 再签到。
      该端点不校验 User-Agent，适合服务端 / 云端定时场景；长效令牌轮换后旧值
      不会立即失效，因此 Actions 里存一份即可长期复用，无需回写 Secret。

  通道 A（兼容；5.5.x 及更早 / 未加密登录态）· Secret WB_ACCESS_TOKEN
      短效接口令牌直通鉴权，行为与原 v2.0.0 完全一致。
      旧变量名 WORKBUDDY_ACCESS_TOKEN / WORKBUDDY_TOKEN 仍被接受（向后兼容）。

  通道 F（本机运行）· 本机登录态文件 workbuddy-desktop.info
      登录态为明文时直接读取；若已是 5.6.2+ 加密信封，则明确报错并给出取得
      长效令牌的路径，不再静默鉴权失败。

两个 Secret 都填时 **通道 R 优先**。

其他同步新版的地方：
  - 积分余额字段：新版接口返回复数 total_credits，旧脚本只认单数 total_credit，
    导致 balance 恒为 null —— 本版补齐复数候选名。
  - 日志脱敏收紧：Actions 日志在公开仓库里人人可读，mask_token() 不再回显任何
    字符片段，只报存在性与长度。

失败推送（可选）：
  若签到结果为 status!=ok，会读取本地配置文件
  ~/.workbuddy/scripts/notify_config.json（若存在），向微信通道推送失败提醒。
  支持：企业微信群机器人 webhook / PushPlus / Bark / Server酱。配置缺失则静默跳过。

成功推送（可选，默认关闭）：
  在 notify_config.json 中设置 "success_notify": true 后，
  签到成功（本次新签到 / 今日已签跳过）也会向同一组微信通道推送一条播报。
  默认不开启，保持「静默无打扰」；仅失败时提醒。

安全约定：
  - 不打印 token / accessToken / refreshToken 明文（输出只含存在性 / 长度）
  - 不修改本机登录态文件
  - 推送密钥只存在于本地 notify_config.json 或 GitHub Secrets，永不进入仓库
  - 异常只记录失败原因，最多重试 1 次，不无限重试

用法：
  python workbuddy_checkin.py            # 查询 + 必要时领取
  python workbuddy_checkin.py --check-only   # 仅查询状态（只读，不领取）
  python workbuddy_checkin.py --no-notify    # 跳过全部推送与桌面通知（调试用）
  python workbuddy_checkin.py --diagnose     # 环境自检（Python/凭据/网络/桌面会话/微信配置）
  python workbuddy_checkin.py --init-config  # 生成 notify_config.json.example 模板
  python workbuddy_checkin.py --help         # 显示帮助
  python workbuddy_checkin.py --version      # 显示版本
  成功推送开关见 ~/.workbuddy/scripts/notify_config.json 的 "success_notify"
"""

import sys

# Python 版本守卫：太旧时给出友好提示，而不是抛出一堆堆栈
if sys.version_info < (3, 6):
    sys.stderr.write(
        "WorkBuddy签到助手：需要 Python 3.6+，当前为 %s。\n"
        "请安装 Python 3.8+（https://www.python.org/downloads/，勾选 Add to PATH），\n"
        "或直接使用 WorkBuddy 自带的托管 Python（~/.workbuddy/binaries/python）。\n"
        % sys.version.split()[0])
    sys.exit(2)

import json
import os
import socket
import subprocess
import time
import urllib.request
import urllib.error
import urllib.parse

# ---- 配置 ----
def _auth_candidates():
    """按操作系统返回 WorkBuddy 登录态文件候选路径，依次探测。"""
    home = os.path.expanduser("~")
    cands = []
    if sys.platform.startswith("win"):
        for env in ("LOCALAPPDATA", "APPDATA"):
            base = os.environ.get(env, "")
            if base:
                cands.append(os.path.join(
                    base, "CodeBuddyExtension", "Data", "Public",
                    "auth", "workbuddy-desktop.info"))
    elif sys.platform == "darwin":
        cands.append(os.path.join(
            home, "Library", "Application Support", "CodeBuddyExtension",
            "Data", "Public", "auth", "workbuddy-desktop.info"))
    else:  # linux / 其他类 Unix
        cands.append(os.path.join(
            home, ".config", "CodeBuddyExtension", "Data", "Public",
            "auth", "workbuddy-desktop.info"))
    # 兜底：便携版 / 未知布局（与 ~/.workbuddy 同根）
    cands.append(os.path.join(
        home, ".workbuddy", "auth", "workbuddy-desktop.info"))
    return [p for p in cands if p]


STATUS_PATH = "/billing/meter/checkin-activity-status"
CHECKIN_PATH = "/billing/meter/daily-checkin"
HTTP_TIMEOUT = 10
MAX_RETRY = 1
VERSION = "2.2.0-ci"

# 长效令牌刷新端点（插件网关；与桌面客户端刷新所用同一官方接口）
PLUGIN_API = "https://copilot.tencent.com"
REFRESH_PATH = "/v2/plugin/auth/token/refresh"
PLUGIN_DOMAIN = "copilot.tencent.com"

# 失败推送配置（含密钥，仅本地，不入库）
NOTIFY_CONFIG = os.path.join(os.path.expanduser("~"),
                             ".workbuddy", "scripts", "notify_config.json")


def find_auth_file():
    for p in _auth_candidates():
        if os.path.isfile(p):
            return p
    return None


def _looks_like_envelope(value):
    """判断凭据是不是 5.6.2+ 的加密信封（云端无法解密）。

    value 可能是 str（Secret 里粘贴的原始 JSON 串）或 dict（登录态文件里读出的字段）。
    """
    if isinstance(value, dict):
        return value.get("$wbEncrypted") == 1
    s = (value or "").strip()
    return s.startswith("{") and "$wbEncrypted" in s


def _env_credential():
    """从环境变量读取凭据（CI / GitHub Actions 等无登录态文件的场景）。

    返回 (refresh_token, access_token, domain)，均可能为空串。

    变量名（新名优先，旧名向后兼容）：
      WB_REFRESH_TOKEN                         长效令牌（推荐）
      WB_ACCESS_TOKEN / WORKBUDDY_ACCESS_TOKEN / WORKBUDDY_TOKEN   短效接口令牌
      WB_DOMAIN / WORKBUDDY_DOMAIN / WORKBUDDY_AUTH_DOMAIN          接口域名
    """
    rt = (os.environ.get("WB_REFRESH_TOKEN") or "").strip()
    at = (os.environ.get("WB_ACCESS_TOKEN")
          or os.environ.get("WORKBUDDY_ACCESS_TOKEN")
          or os.environ.get("WORKBUDDY_TOKEN") or "").strip()
    domain = (os.environ.get("WB_DOMAIN")
              or os.environ.get("WORKBUDDY_DOMAIN")
              or os.environ.get("WORKBUDDY_AUTH_DOMAIN")
              or "").strip()
    # 容错：允许传入带协议前缀的域名
    domain = domain.replace("https://", "").replace("http://", "").strip("/")
    return rt, at, domain


def _check_expiry(auth):
    """登录态已过期时给出友好提示（只读取 expiresAt，绝不打印 token）。"""
    raw = auth.get("expiresAt")
    if not raw:
        return  # 无过期字段则跳过检查
    try:
        exp = int(raw)
    except (TypeError, ValueError):
        return
    # 兼容 epoch 毫秒（13 位）/ 秒（10 位）
    if exp > 10 ** 11:
        exp = exp / 1000.0
    if exp <= time.time():
        expire_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp))
        raise RuntimeError(
            "登录态已过期（过期时间 %s），请重新登录 WorkBuddy 客户端后再试" % expire_str)


def _check_env_expiry():
    """短效令牌的本地过期预判（来自 Secret WB_EXPIRES_AT）。

    长效令牌自身不带 expiresAt，不走这里；只在短效直通通道使用。
    字段缺失或格式异常时一律放行，由接口返回真实结果。
    """
    raw = (os.environ.get("WB_EXPIRES_AT") or "").strip()
    if not raw:
        return
    try:
        exp = int(raw)
    except (TypeError, ValueError):
        return
    if exp > 10 ** 11:
        exp = exp / 1000.0
    if exp <= time.time():
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(exp))
        raise RuntimeError("WB_ACCESS_TOKEN 已过期（%s），请更新该 Secret" % when)


def load_token(auth_path):
    """读取本机登录态文件中的 accessToken（明文登录态专用）。

    5.6.2+ 的加密信封在此**明确报错**，而不是把一坨 JSON 当 token 用 ——
    后者会一路带到接口才鉴权失败，排查成本极高。
    """
    with open(auth_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    auth = data.get("auth", {})
    raw = auth.get("accessToken")
    domain = auth.get("domain") or "www.codebuddy.cn"
    if raw is None:
        raise RuntimeError("登录态文件中未找到 accessToken（可能未登录或登录态已失效）")
    if _looks_like_envelope(raw):
        raise RuntimeError(
            "本机登录态是 5.6.2+ 的加密形态（AES-256-GCM 信封），解密密钥不落盘、"
            "只由运行中的客户端在内存中提供，云端 runner 无法解密。\n"
            "  请改用长效令牌：在本机运行 `python scripts/sync_token_to_github.py`，"
            "  由它导出明文长效令牌并写入 Secret WB_REFRESH_TOKEN。")
    _check_expiry(auth)
    return raw, domain


def mask_token(t):
    """脱敏回显：**只报存在性与长度，不回显任何字符片段**。

    Actions 日志在公开仓库里人人可读（--diagnose 与签到步骤都会落日志），
    任何字符片段都等于把凭据咬下一口带走 —— 哪怕是 "看起来安全" 的前 6 后 4。
    需要肉眼核对片段时，请在本机单独运行 sync_token_to_github.py --show-masked。
    """
    if not t:
        return "<empty>"
    return "<已配置，长度 %d，不回显片段>" % len(t)


def refresh_access_token(rt):
    """用长效令牌换取新的接口令牌。

    返回 (access_token, new_refresh_token, err)；成功时 err 为 None。
    该端点不校验 User-Agent，适合云端 / 服务端定时场景。
    """
    req = urllib.request.Request(PLUGIN_API + REFRESH_PATH, data=b"{}", method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Refresh-Token", rt)
    req.add_header("X-Auth-Refresh-Source", "plugin")
    req.add_header("X-Domain", PLUGIN_DOMAIN)
    req.add_header("User-Agent", "WorkBuddy-Checkin-Script/2.1")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return None, None, "HTTP %s" % e.code
    except urllib.error.URLError as e:
        return None, None, "网络错误: %s" % e.reason
    except Exception as e:
        return None, None, "异常: %s" % str(e)[:200]

    if not isinstance(body, dict) or body.get("code") != 0 \
            or not isinstance(body.get("data"), dict):
        return None, None, "code=%s %s" % (
            body.get("code") if isinstance(body, dict) else "?",
            (body.get("msg") or body.get("message") or "") if isinstance(body, dict) else "")
    data = body["data"]
    at = data.get("accessToken") or ""
    new_rt = data.get("refreshToken") or ""
    if not at:
        return None, None, "刷新应答缺少 accessToken"
    return at, new_rt, None


def resolve_credential(result):
    """决定本次用哪个凭据，并把来源写进 result['detail']。

    优先级：
      1) WB_REFRESH_TOKEN —— 长效令牌（5.6.2+ 推荐），先换取接口令牌
      2) WB_ACCESS_TOKEN / WORKBUDDY_ACCESS_TOKEN —— 短效令牌直通（兼容）
      3) 本机登录态文件 —— 仅当为明文登录态时可用
    返回 (token, domain, err)；err 非空表示无法取得可用凭据。
    """
    rt, at, env_domain = _env_credential()

    if rt:
        if _looks_like_envelope(rt):
            return None, None, (
                "WB_REFRESH_TOKEN 填的是加密信封（5.6.2+ 登录态原样粘贴），云端无法解密。"
                "请在本机运行 `python scripts/sync_token_to_github.py` 导出**明文**长效令牌后再填入。")
        new_at, new_rt, err = refresh_access_token(rt)
        if not new_at:
            return None, None, (
                "长效令牌刷新失败：%s。请在本机重新运行 "
                "`python scripts/sync_token_to_github.py` 更新 WB_REFRESH_TOKEN。" % err)
        result["detail"]["auth_source"] = "refresh_token"
        result["detail"]["credential"] = "refresh_token（长效令牌）"
        result["detail"]["rt_rotated"] = bool(new_rt and new_rt != rt)
        result["detail"]["token_masked"] = mask_token(new_at)
        result["detail"]["auth_file"] = "(env: WB_REFRESH_TOKEN)"
        return new_at, (env_domain or "www.codebuddy.cn"), None

    if at:
        if _looks_like_envelope(at):
            return None, None, (
                "WB_ACCESS_TOKEN 填的是加密信封（5.6.2+ 登录态原样粘贴），云端无法解密。"
                "请改用长效令牌：在本机运行 `python scripts/sync_token_to_github.py` "
                "设置 WB_REFRESH_TOKEN。")
        try:
            _check_env_expiry()
        except Exception as e:
            return None, None, str(e)
        result["detail"]["auth_source"] = "env"
        result["detail"]["credential"] = "access_token（短效直通）"
        result["detail"]["token_masked"] = mask_token(at)
        result["detail"]["auth_file"] = "(env: WB_ACCESS_TOKEN)"
        return at, (env_domain or "www.codebuddy.cn"), None

    auth_path = find_auth_file()
    if not auth_path:
        return None, None, (
            "未配置任何凭据，也未找到本机登录态文件。请设置 Secret WB_REFRESH_TOKEN"
            "（推荐，长效令牌）或 WB_ACCESS_TOKEN（短效令牌直通）。")
    try:
        token, domain = load_token(auth_path)
    except Exception as e:
        return None, None, "读取登录态失败: %s" % e
    result["detail"]["auth_source"] = "file"
    result["detail"]["credential"] = "access_token（本机登录态文件）"
    result["detail"]["auth_file"] = auth_path
    result["detail"]["token_masked"] = mask_token(token)
    return token, (env_domain or domain), None


def api_call(base, path, token, payload=None, method="POST"):
    url = base + path
    data = json.dumps(payload if payload is not None else {}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer %s" % token)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "WorkBuddy-Checkin-Script/2.1")
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, {"raw": body}
    except urllib.error.HTTPError as e:
        # 非 2xx 也读取响应体（如已签到返回的 HTTP 400 / code=10001）
        try:
            body = e.read().decode("utf-8", "replace")
            try:
                return e.code, json.loads(body)
            except json.JSONDecodeError:
                return e.code, {"raw": body}
        except Exception:
            return e.code, {"raw": ""}


# ── 接口响应的「白名单压缩」──────────────────────────────────────
# 为什么必须做：完整响应会被 result["detail"] 带进 stdout，而 workflow 用
# `python scripts/workbuddy_checkin.py | tee result.json` 把 stdout 整份写进
# **Actions 运行日志**（公开仓库里人人可读、长期留存）。一旦接口在 data 里
# 回带用户资料（手机号 / 邮箱 / userId 等），就会直接展示在公开日志中 ——
# 这是「依赖上游不返回敏感字段」的不可控敞口。
#
# 本函数把响应压成白名单：stdout / result.json / artifact / Step Summary
# 四处输出口径一次性统一，与摘要层（summarize_result.py）保持一致。
#
# 本机调试需要完整响应时：set WB_DUMP_RESP=1（CI 中永不设置）。
_RESP_KEEP = ("code", "msg", "message", "today_checked_in", "signed",
              "success", "credit", "daily_credit", "today_credit",
              "streak", "streak_days", "balance", "total_credits")


def _slim_resp(body):
    """把接口响应压成白名单字段。

    保留：结论字段的值 + 完整字段名清单（排错时能看到响应结构）。
    丢弃：其余一切内容（可能含用户资料或未来新增的未知字段）。
    """
    if not isinstance(body, dict):
        # 非 dict（如 {"raw": "<html>..."} 里的字符串）只报类型，绝不带内容
        return {"_type": type(body).__name__}
    out = {}
    for k in _RESP_KEEP:
        if k in body:
            out[k] = body[k]
    data = body.get("data")
    if isinstance(data, dict):
        d = {}
        for k in _RESP_KEEP:
            if k in data:
                d[k] = data[k]
        d["_keys"] = sorted(data.keys())   # 只留字段名，不留值
        out["data"] = d
    out["_keys"] = sorted(body.keys())
    return out


def _resp_for_detail(body):
    """按 WB_DUMP_RESP 决定 detail 里放完整响应还是白名单压缩版。"""
    if os.environ.get("WB_DUMP_RESP") == "1":
        return body
    return _slim_resp(body)


def _extract_balance(*bodies):
    """从接口响应中尽力提取「积分余额」（total / balance 类字段）。

    不同版本接口返回的余额字段名不统一。**5.6.2+ 返回的是复数 total_credits**，
    旧脚本只认单数 total_credit，导致 balance 恒为 null —— 本版补齐复数候选名。
    找不到则返回 None（不影响签到主流程）。
    """
    candidates = (
        "total_credits", "total_credit", "total_credit_balance", "credits",
        "total_points", "points_balance", "credit_balance", "balance",
        "remain_credit", "remain_credits", "remain", "score", "integral",
        "totalCredits", "totalCredit", "pointsBalance", "balanceCredit",
    )
    sections = ("", "data", "result", "data.result")
    for body in bodies:
        if not isinstance(body, dict):
            continue
        for sec in sections:
            node = body
            for part in sec.split(".") if sec else []:
                if isinstance(node, dict):
                    node = node.get(part)
                else:
                    node = None
                    break
            if not isinstance(node, dict):
                # 顶层（sec 为空字符串）直接看 body 本身
                node = body if sec == "" else None
            if not isinstance(node, dict):
                continue
            for k in candidates:
                v = node.get(k)
                if isinstance(v, (int, float)):
                    return v
    return None


# ---------------- 失败推送（微信） ----------------

def load_notify_config():
    if not os.path.isfile(NOTIFY_CONFIG):
        return None
    try:
        with open(NOTIFY_CONFIG, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            return None
        return cfg
    except Exception:
        return None


def _http_post_json(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "WorkBuddy-Checkin-Script/2.1")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def notify_via_wecom(webhook, title, content):
    payload = {"msgtype": "markdown", "markdown": {"content": content}}
    return _http_post_json(webhook, payload)


def notify_via_pushplus(token, title, content):
    url = "https://www.pushplus.plus/send"
    payload = {"token": token, "title": title,
               "content": content, "template": "markdown"}
    return _http_post_json(url, payload)


def notify_via_bark(bark_url, title, content):
    # bark_url 形如 https://api.day.app/<key>/ ，脚本自动拼接标题与内容
    base = bark_url.rstrip("/")
    url = "%s/%s/%s" % (base,
                        urllib.parse.quote(title),
                        urllib.parse.quote(content))
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "WorkBuddy-Checkin-Script/2.1")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def notify_via_serverchan(sendkey, title, content):
    """Server酱（方糖，ServerChan）推送到个人微信。

    - Turbo 版（SendKey 形如 SCTxxxx）：POST https://sctapi.ftqq.com/<sendkey>.send
      表单参数 title / desp（desp 支持 Markdown）
    - 旧版（SendKey 形如 SCUxxxx）：POST https://sc.ftqq.com/<sendkey>.send
      表单参数 text / desp
    """
    if sendkey.startswith("SCU"):
        url = "https://sc.ftqq.com/%s.send" % sendkey
        data = urllib.parse.urlencode({"text": title, "desp": content}).encode("utf-8")
    else:
        url = "https://sctapi.ftqq.com/%s.send" % sendkey
        data = urllib.parse.urlencode({"title": title, "desp": content}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("User-Agent", "WorkBuddy-Checkin-Script/2.1")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def _dispatch_channels(cfg, title, content):
    """按本地配置向所有已启用的微信通道推送；返回各通道结果列表（不含任何密钥）。"""
    results = []
    # 企业微信群机器人 webhook（优先级最高）
    webhook = cfg.get("wecom_webhook")
    if webhook:
        try:
            st, _ = notify_via_wecom(webhook, title, content)
            results.append("wecom:%s" % st)
        except Exception as e:
            results.append("wecom_err:%s" % e)
    # PushPlus（推送到个人微信）
    token = cfg.get("pushplus_token")
    if token:
        try:
            st, _ = notify_via_pushplus(token, title, content)
            results.append("pushplus:%s" % st)
        except Exception as e:
            results.append("pushplus_err:%s" % e)
    # Bark（iOS 推送）
    bark = cfg.get("bark_url")
    if bark:
        try:
            st, _ = notify_via_bark(bark, title, content)
            results.append("bark:%s" % st)
        except Exception as e:
            results.append("bark_err:%s" % e)
    # Server酱（方糖）推送到个人微信
    sc = cfg.get("serverchan_sendkey")
    if sc:
        try:
            st, _ = notify_via_serverchan(sc, title, content)
            results.append("serverchan:%s" % st)
        except Exception as e:
            results.append("serverchan_err:%s" % e)
    return results


def notify_failure(res):
    """签到失败时，按本地配置推送微信提醒；配置缺失则静默跳过。"""
    cfg = load_notify_config()
    res.setdefault("detail", {})["notify_config_present"] = cfg is not None
    res["detail"]["notify_enabled"] = cfg.get("enabled") if cfg else None
    if not cfg:
        return
    if cfg.get("enabled") is False:
        return

    title = "⚠️ WorkBuddy签到助手 · 签到失败"
    now = time.strftime("%Y-%m-%d %H:%M:%S")  # 本机时区（北京时间）
    msg = res.get("msg", "未知原因")
    src = res.get("detail", {}).get("auth_source") or res.get("detail", {}).get("auth_file", "未知")

    content = (
        "### ⚠️ WorkBuddy签到助手 · 签到失败\n\n"
        "> **时间**：%s\n\n"
        "> **原因**：%s\n\n"
        "> **凭据来源**：%s\n\n"
        "> **处理建议**：若为定时任务（GitHub Actions），请在本机重新运行 "
        "`python scripts/sync_token_to_github.py` 更新 Secret `WB_REFRESH_TOKEN`；"
        "若为本机运行，请确认 WorkBuddy 客户端已登录、电脑联网。\n"
    ) % (now, msg, src)

    results = _dispatch_channels(cfg, title, content)
    # 仅记录推送动作结果（不含任何密钥 / token），便于排查
    res["detail"]["notify"] = results


def notify_success(res):
    """签到成功（新签到 / 今日已签跳过）时，按本地配置推送微信播报。

    仅当 notify_config.json 中 success_notify=true 时才推送；否则静默。
    与失败推送共用通道与密钥配置。
    """
    cfg = load_notify_config()
    res.setdefault("detail", {})["notify_config_present"] = cfg is not None
    res["detail"]["notify_enabled"] = cfg.get("enabled") if cfg else None
    res["detail"]["notify_success_notify_flag"] = cfg.get("success_notify") if cfg else None
    if not cfg:
        return
    if cfg.get("enabled") is False:
        return
    if not cfg.get("success_notify"):
        return

    now = time.strftime("%Y-%m-%d %H:%M:%S")  # 本机时区（北京时间）
    action = res.get("action")
    # 仅对明确的成功态推送（新签到 / 今日已签跳过）；其他态（失败 / 纯查询）不推
    if action not in ("clicked", "skip_already_signed"):
        return
    msg = res.get("msg", "")
    points = res.get("points")
    streak = res.get("detail", {}).get("streak_days")
    balance = res.get("balance")

    if action == "skip_already_signed":
        title = "✅ WorkBuddy签到助手 · 今日已签"
        content = (
            "### ✅ WorkBuddy签到助手 · 今日已签\n\n"
            "> **时间**：%s\n\n"
            "> **状态**：今日已签到，无需重复领取（幂等保护）\n\n"
            "> **说明**：系统定时任务 / 技能已正常执行，无需处理。\n"
        ) % now
    else:
        title = "✅ WorkBuddy签到助手 · 签到成功"
        lines = (
            "### ✅ WorkBuddy签到助手 · 签到成功\n\n"
            "> **时间**：%s\n\n"
            "> **状态**：%s\n"
        ) % (now, msg)
        if points:
            lines += "> **积分**：+%s\n\n" % points
        if streak:
            lines += "> **连续天数**：第 %s 天\n\n" % streak
        if balance is not None:
            lines += "> **当前积分余额**：%s\n\n" % balance
        lines += "> **说明**：系统定时任务 / 技能已正常执行，无需处理。\n"
        content = lines

    results = _dispatch_channels(cfg, title, content)
    res["detail"]["notify_success"] = results


def notify_system(res):
    """签到完成后弹出操作系统级桌面通知（toast / 气球提示），展示结果 + 积分余额。

    跨平台兼容 Windows / macOS / Linux；best-effort、非阻塞、失败静默，
    绝不影响签到结果与退出码。受 --no-notify 一并抑制（与微信推送调试开关一致）。
    """
    try:
        status = res.get("status")
        title = "WorkBuddy签到助手"
        if status == "error":
            body = "签到失败：" + str(res.get("msg", ""))
        else:
            body = str(res.get("msg", "签到完成"))
            bal = res.get("balance")
            if bal is not None:
                body += " ｜ 当前积分余额：" + str(bal)
        _system_toast(title, body)
    except Exception:
        pass  # 通知失败绝不影响签到


def _system_toast(title, body):
    """按操作系统分发到原生命令；任何异常一律忽略。"""
    plat = sys.platform
    try:
        if plat == "darwin":
            msg = body.replace('"', "'")
            subprocess.run(
                ["osascript", "-e",
                 'display notification "%s" with title "%s"' % (msg, title)],
                timeout=5, check=False,
            )
        elif plat.startswith("linux"):
            subprocess.run(["notify-send", title, body], timeout=5, check=False)
        elif plat == "win32":
            _win_toast(title, body)
    except Exception:
        pass


def _win_toast(title, body):
    """Windows：用 .NET 气球提示（非阻塞、约 5s）。PowerShell 不可用或被策略拦截时静默跳过。"""
    safe_title = title.replace("'", "''")
    safe_body = body.replace("'", "''")
    ps = ("Add-Type -AssemblyName System.Windows.Forms;"
          "Add-Type -AssemblyName System.Drawing;"
          "$n=New-Object System.Windows.Forms.NotifyIcon;"
          "$n.Icon=[System.Drawing.SystemIcons]::Information;"
          "$n.Visible=$true;"
          "$n.ShowBalloonTip(5000,'%s','%s','Info');"
          "Start-Sleep -Milliseconds 150;"
          "$n.Dispose()") % (safe_title, safe_body)
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        timeout=10, check=False,
    )


# ---------------- 主流程 ----------------

def run(check_only):
    result = {"status": "unknown", "action": None, "points": None,
              "balance": None, "msg": "", "detail": {}}

    # 1) 解析凭据（长效令牌 > 短效令牌 > 本机登录态文件）
    token, domain, err = resolve_credential(result)
    if err:
        result.update(status="error", msg=err)
        return result
    result["detail"]["domain"] = domain
    base = "https://%s/v2" % domain

    attempt = 0
    last_err = None
    while attempt <= MAX_RETRY:
        attempt += 1
        try:
            # 1) 查询今日状态
            st_code, st_body = api_call(base, STATUS_PATH, token)
            result["detail"]["status_http"] = st_code
            result["detail"]["status_resp"] = _resp_for_detail(st_body)
            # 从状态响应中提前提取积分余额（领取分支会用领取响应再覆盖一次）
            result["balance"] = _extract_balance(st_body)
            result["detail"]["balance"] = result["balance"]

            # 判断是否已签到：兼容多种返回形态
            today_signed = False
            if isinstance(st_body, dict):
                if st_body.get("today_checked_in") is True:
                    today_signed = True
                elif st_body.get("data", {}).get("today_checked_in") is True:
                    today_signed = True
                elif str(st_body.get("code")) == "10001":
                    today_signed = True

            if check_only:
                bal_txt = ("，当前积分余额 %s" % result["balance"]) if result.get("balance") is not None else ""
                result.update(
                    status="ok",
                    action="skip_check_only",
                    msg="状态查询成功（未执行领取）" + bal_txt,
                )
                result["detail"]["today_signed"] = today_signed
                return result

            if today_signed:
                bal_txt = ("，当前积分余额 %s" % result["balance"]) if result.get("balance") is not None else ""
                result.update(status="ok", action="skip_already_signed",
                              msg="今日已签到，无需重复领取" + bal_txt)
                return result

            # 2) 领取签到
            ck_code, ck_body = api_call(base, CHECKIN_PATH, token)
            result["detail"]["checkin_http"] = ck_code
            result["detail"]["checkin_resp"] = _resp_for_detail(ck_body)

            if isinstance(ck_body, dict):
                code = str(ck_body.get("code", ""))
                msg = ck_body.get("msg") or ck_body.get("message") or ""
                data = ck_body.get("data") if isinstance(ck_body.get("data"), dict) else {}
                # 已签/重复提示（幂等保护）
                if code == "10001" or "已签到" in msg or "今天已签到" in msg:
                    result.update(status="ok", action="skip_already_signed",
                                  msg="今日已签到（接口返回 code=10001）")
                    return result
                # 领取成功判定：HTTP 2xx 且业务码为成功（兼容无 code / code=0 / code=200）
                success_code = code in ("", "0", "200")
                if 200 <= ck_code < 300 and success_code:
                    credit = (ck_body.get("credit") or data.get("credit")
                              or data.get("daily_credit") or data.get("today_credit"))
                    streak = ck_body.get("streak_days") or data.get("streak_days")
                    # 领取响应若带回余额则覆盖状态响应中的值
                    bbal = _extract_balance(ck_body)
                    if bbal is not None:
                        result["balance"] = bbal
                        result["detail"]["balance"] = bbal
                    bal_txt = ("，当前积分余额 %s" % result["balance"]) if result.get("balance") is not None else ""
                    result.update(status="ok", action="clicked",
                                  points=credit,
                                  msg="领取成功" + (("，+%s 积分" % credit) if credit else "") +
                                      (("，连续第 %s 天" % streak) if streak else "") + bal_txt)
                    result["detail"]["streak_days"] = streak
                    return result
                # 其余视为失败（含 2xx 但业务码异常、或非 2xx）
                result.update(status="error", action="failed",
                              msg=msg or ("HTTP %s（业务码 %s）" % (ck_code, code)))
                return result
            else:
                result.update(status="error", action="failed",
                              msg="领取接口返回非 JSON: %s" % ck_body.get("raw", "")[:200])
                return result

        except urllib.error.HTTPError as e:
            last_err = "HTTP %s: %s" % (e.code, e.reason)
        except urllib.error.URLError as e:
            last_err = "网络错误: %s" % e.reason
        except Exception as e:
            last_err = "异常: %s" % e

        # 重试前稍作等待
        if attempt <= MAX_RETRY:
            time.sleep(2)

    result.update(status="error", msg="重试 %d 次后仍失败: %s" % (MAX_RETRY, last_err))
    return result


def write_log(res):
    """把每次运行结果追加写入脚本同目录的 checkin.log（本地核查用，不含 token）。"""
    try:
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "checkin.log")
        line = "%s | status=%s | action=%s | msg=%s\n" % (
            time.strftime("%Y-%m-%d %H:%M:%S"),
            res.get("status"), res.get("action"), res.get("msg"))
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass  # 写日志失败绝不影响签到


# ---------------- 环境自检与配置模板 ----------------

def _has_desktop_session():
    """best-effort 探测当前是否存在桌面图形会话（影响系统通知能否弹出）。

    探测失败或无法确定时返回 "unknown"，绝不影响签到主流程。
    """
    try:
        if sys.platform.startswith("win"):
            # SM_REMOTESESSION：1=远端会话（通常为无桌面/服务态），0=本地控制台
            try:
                import ctypes
                return "yes" if ctypes.windll.user32.GetSystemMetrics(0x1000) == 0 else "remote/no"
            except Exception:
                return "unknown"
        elif sys.platform == "darwin":
            # macOS 桌面环境一般存在；无法可靠区分锁屏，保守返回 yes
            return "yes"
        else:
            # Linux/类 Unix：有 $DISPLAY 或 $WAYLAND_DISPLAY 通常代表有桌面
            if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
                return "yes"
            return "no"
    except Exception:
        return "unknown"


def write_config_example():
    """生成 notify_config.json.example 模板（不含任何真实密钥，可放心查看/转发）。"""
    path = NOTIFY_CONFIG + ".example"
    example = {
        "enabled": True,
        "success_notify": False,
        "wecom_webhook": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=替换为你的群机器人KEY",
        "pushplus_token": "替换为你的PushPlus_token（个人微信推送）",
        "bark_url": "https://api.day.app/替换为你的Bark_KEY/",
        "serverchan_sendkey": "替换为你的Server酱SendKey（方糖，个人微信推送，形如 SCTxxxxx）"
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(example, f, ensure_ascii=False, indent=2)
    return path


def diagnose():
    """环境自检：检查 Python / 凭据 / 网络 / 桌面会话 / 微信配置。

    只读、不触发任何签到请求（长效令牌会做一次换取尝试，用于确认令牌是否有效；
    刷新本身不产生副作用），便于用户首次安装后快速确认「能不能用」。
    返回结构化 dict，由 main() 以 JSON 打印。
    """
    report = {"version": VERSION, "python": {}, "credential": {}, "network": {},
              "desktop": {}, "notify_config": {}}

    # 1) Python 版本
    report["python"] = {
        "version": sys.version.split()[0],
        "ok": sys.version_info >= (3, 6),
        "note": "" if sys.version_info >= (3, 6) else "低于 3.6，请升级 Python 或改用 WorkBuddy 托管 Python",
    }

    # 2) 凭据：长效令牌 > 短效令牌 > 本机登录态文件
    rt, at, env_domain = _env_credential()
    cred = report["credential"]
    if rt:
        cred["mode"] = "refresh_token（长效令牌，推荐）"
        cred["present"] = True
        cred["source"] = "WB_REFRESH_TOKEN"
        cred["masked"] = mask_token(rt)
        cred["envelope"] = _looks_like_envelope(rt)
        if cred["envelope"]:
            cred["hint"] = ("填的是加密信封，云端无法解密；请改为填入明文长效令牌"
                            "（本机运行 sync_token_to_github.py 导出）")
        else:
            # 只做换取尝试，不签到（刷新本身不产生副作用）
            _at, _new_rt, err = refresh_access_token(rt)
            cred["refresh_ok"] = bool(_at)
            if err:
                cred["refresh_error"] = err
    elif at:
        cred["mode"] = "access_token（短效直通，兼容旧版）"
        cred["present"] = True
        cred["source"] = "WB_ACCESS_TOKEN / WORKBUDDY_ACCESS_TOKEN"
        cred["masked"] = mask_token(at)
        cred["envelope"] = _looks_like_envelope(at)
        if cred["envelope"]:
            cred["hint"] = ("填的是加密信封，云端无法解密；请改用 WB_REFRESH_TOKEN"
                            "（本机运行 sync_token_to_github.py 导出长效令牌）")
    else:
        auth_path = find_auth_file()
        cred["mode"] = "access_token（本机登录态文件）"
        if auth_path:
            cred["found"] = True
            cred["path"] = auth_path
            try:
                token, domain = load_token(auth_path)
                cred["token_present"] = True
                cred["domain"] = domain
                cred["expired"] = False
                cred["masked"] = mask_token(token)
            except Exception as e:
                cred["token_present"] = False
                cred["error"] = str(e)
                cred["expired"] = ("过期" in str(e))
        else:
            cred["found"] = False
            cred["hint"] = ("未找到登录态文件，也未配置 WB_REFRESH_TOKEN / WB_ACCESS_TOKEN；"
                            "请在 CI 中配置 Secret，或确认本机 WorkBuddy 客户端已登录")

    cred["domain"] = env_domain or cred.get("domain") or "www.codebuddy.cn"

    # 3) 网络连通性（DNS 解析 best-effort）
    #    只报「能否解析」，**不输出解析到的 IP** —— diagnose 会进公开的 Actions 日志，
    #    而解析结果随 runner 地区而变，对排障无额外价值，属可省的输出。
    domain = cred.get("domain") or "www.codebuddy.cn"
    try:
        socket.gethostbyname(domain)
        report["network"]["dns_ok"] = True
        report["network"]["host"] = domain
    except Exception as e:
        report["network"]["dns_ok"] = False
        report["network"]["host"] = domain
        report["network"]["error"] = str(e)

    # 4) 桌面会话（影响系统通知弹窗）
    report["desktop"]["session"] = _has_desktop_session()
    report["desktop"]["note"] = (
        "存在桌面会话，系统通知可正常弹出" if report["desktop"]["session"] == "yes"
        else "未检测到桌面会话（如锁屏/无 GUI 服务态），系统通知可能不弹出；stdout 与 checkin.log 仍可记录结果"
    )

    # 5) 微信推送配置
    cfg = load_notify_config()
    if cfg is None:
        report["notify_config"]["present"] = False
        report["notify_config"]["hint"] = "未配置（可选）；运行 --init-config 生成模板"
    else:
        report["notify_config"]["present"] = True
        report["notify_config"]["enabled"] = cfg.get("enabled", True)
        report["notify_config"]["success_notify"] = bool(cfg.get("success_notify"))
        channels = [k for k in ("wecom_webhook", "pushplus_token", "bark_url", "serverchan_sendkey") if cfg.get(k)]
        report["notify_config"]["channels"] = channels
        # 简单校验：enabled 但无通道 = 配了也不会推
        if cfg.get("enabled", True) and not channels:
            report["notify_config"]["warn"] = "enabled=true 但未填写任何通道，推送不会生效"

    return report


USAGE = (
    "WorkBuddy签到助手（接口直签）\n\n"
    "用法：\n"
    "  python workbuddy_checkin.py                # 查询今日状态 + 必要时领取\n"
    "  python workbuddy_checkin.py --check-only   # 仅查询状态（只读，不领取）\n"
    "  python workbuddy_checkin.py --no-notify    # 跳过全部推送与桌面通知（调试用）\n"
    "  python workbuddy_checkin.py --diagnose     # 环境自检（Python/凭据/网络/桌面会话/微信配置）\n"
    "  python workbuddy_checkin.py --init-config  # 生成 notify_config.json.example 模板\n"
    "  python workbuddy_checkin.py --help         # 显示本帮助\n"
    "  python workbuddy_checkin.py --version      # 显示版本号\n\n"
    "凭据（三个通道，长效令牌优先）：\n"
    "  WB_REFRESH_TOKEN   长效令牌（推荐；5.6.2+ 客户端必用，云端换取接口令牌）\n"
    "  WB_ACCESS_TOKEN    短效接口令牌直通（兼容 5.5.x 及更早 / 未加密登录态）\n"
    "  本机登录态文件     workbuddy-desktop.info（仅明文登录态可用）\n"
    "其他环境变量：WB_DOMAIN / WB_EXPIRES_AT\n"
    "退出码：成功 0 / 失败 1（便于自动化判断是否推送告警）\n"
    "签到成功后会在结果中展示当前积分余额（若接口返回 balance / total_credits 等字段）。\n"
    "微信推送开关见 ~/.workbuddy/scripts/notify_config.json 的 \"success_notify\" 字段。\n"
)


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(USAGE)
        sys.exit(0)
    if "--version" in sys.argv:
        print("workbuddy_checkin %s" % VERSION)
        sys.exit(0)
    # 环境自检：只读、不签到，便于首次安装后确认可用性
    if "--diagnose" in sys.argv:
        rep = diagnose()
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        sys.exit(0)
    # 生成微信推送配置模板（可选）
    if "--init-config" in sys.argv:
        p = write_config_example()
        print("已生成配置模板：%s" % p)
        print("请复制为 notify_config.json 并填入你的微信通道密钥（或使用默认值保持关闭）。")
        sys.exit(0)
    check_only = "--check-only" in sys.argv
    no_notify = "--no-notify" in sys.argv
    try:
        res = run(check_only)
    except Exception as e:
        res = {"status": "error", "action": None, "points": None,
               "msg": "脚本未捕获异常: %s" % e, "detail": {}}
    # 输出结果（不含任何真实 token）
    # 失败推送（配置缺失则跳过；--no-notify 用于调试）
    if not no_notify and res.get("status") != "ok":
        try:
            notify_failure(res)
        except Exception:
            pass  # 推送失败不影响签到结果与退出码
    # 成功推送（仅当 notify_config.json 中 success_notify=true；--no-notify 用于调试）
    if not no_notify and res.get("status") == "ok":
        try:
            notify_success(res)
        except Exception:
            pass  # 推送失败不影响签到结果与退出码
    # 系统桌面通知（跨平台 toast / 气球；--no-notify 一并抑制；失败静默）
    if not no_notify:
        try:
            notify_system(res)
        except Exception:
            pass
    # 输出结果（不含任何真实 token）—— 移后以便包含推送状态
    print(json.dumps(res, ensure_ascii=False, indent=2))
    # 本地运行日志（系统定时任务无对话汇报，靠它核查）
    write_log(res)
    # 退出码：成功 0，失败 1，便于自动化判断是否推送告警
    sys.exit(0 if res.get("status") == "ok" else 1)


if __name__ == "__main__":
    main()
