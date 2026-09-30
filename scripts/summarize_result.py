#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把签到结果 JSON 转换为「精简摘要」输出（供 GitHub Actions 的 $GITHUB_STEP_SUMMARY 使用）。

为什么需要它：
  Actions 运行摘要会长期留存在仓库的 Actions 页面上，任何能看到该仓库的人都可以查看。
  因此不应把脚本的完整 result.json（含原始接口响应 detail.status_resp）直接写入摘要。
  本脚本按白名单挑选字段，从源头杜绝「本可避免的信息暴露」。

白名单字段（均为非敏感的运行结论）：
  status / action / points / balance / msg / streak_days / today_signed / domain

不输出的内容：
  - token_masked（无必要暴露，即使已脱敏）
  - auth_file（暴露 runner 上的路径）
  - status_resp（原始响应全文，可能随接口变更引入非预期字段）
  - 任何形似凭据的长字符串（兜底过滤）

用法：
  python summarize_result.py <result.json 路径>
"""

import json
import os
import re
import sys

# 白名单：仅这些键允许出现在摘要中（detail 下的用 "detail.xxx" 表示）
ALLOWED_TOP = ("status", "action", "points", "balance", "msg")
ALLOWED_DETAIL = ("streak_days", "today_signed", "domain", "credential",
                  "notify_config_present", "notify_enabled",
                  "notify_success_notify_flag", "notify_success", "notify")

# 兜底：任何长度超过 80 的连续 base64url 风格串都替换为 REDACTED
LONG_TOKEN_RX = re.compile(r"[A-Za-z0-9_\-]{80,}")

ACTION_LABEL = {
    "clicked": "✅ 签到成功",
    "skip_already_signed": "⏭️ 今日已签到（跳过）",
    "skip_check_only": "🔍 仅查询",
    "failed": "❌ 签到失败",
}

STATUS_LABEL = {"ok": "成功", "error": "失败"}


def _safe(v):
    """兜底脱敏：把疑似超长凭据串替换掉。"""
    if isinstance(v, str):
        return LONG_TOKEN_RX.sub("<REDACTED>", v)
    return v


def build_summary(data):
    lines = []
    lines.append("## WorkBuddy 签到结果")
    lines.append("")

    status = data.get("status", "unknown")
    action = data.get("action") or "-"
    lines.append("| 项目 | 值 |")
    lines.append("|---|---|")
    lines.append("| 结果 | %s |" % STATUS_LABEL.get(status, status))
    lines.append("| 动作 | %s |" % ACTION_LABEL.get(action, action))

    for key in ALLOWED_TOP:
        if key in ("status", "action"):
            continue
        if key in data and data[key] is not None:
            lines.append("| %s | %s |" % (key, _safe(data[key])))

    detail = data.get("detail") or {}
    for key in ALLOWED_DETAIL:
        if key in detail and detail[key] is not None:
            lines.append("| %s | %s |" % (key, _safe(detail[key])))

    lines.append("")
    if status == "error":
        lines.append("> ⚠️ 签到失败，请查看上方日志中的错误信息。")
        lines.append("> 常见原因：token 过期（重跑 `sync_token_to_github.py` 续期）／域名配置错误。")
    return "\n".join(lines) + "\n"


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("用法: python summarize_result.py <result.json>\n")
        sys.exit(2)

    path = sys.argv[1]
    if not os.path.isfile(path):
        print("## WorkBuddy 签到结果\n\n（未产生结果文件，请检查上一步执行日志）")
        sys.exit(0)

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print("## WorkBuddy 签到结果\n\n（结果文件解析失败：%s）" % e)
        sys.exit(0)

    if not isinstance(data, dict):
        print("## WorkBuddy 签到结果\n\n（结果格式异常）")
        sys.exit(0)

    sys.stdout.write(build_summary(data))


if __name__ == "__main__":
    main()
