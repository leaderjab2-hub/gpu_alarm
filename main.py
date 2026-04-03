import os
import re
import logging
import httpx
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, filters, ContextTypes

load_dotenv()

BOT_TOKEN    = os.getenv("BOT_TOKEN")
CHANNEL_ID   = -1002875090355
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

KST = timezone(timedelta(hours=9))
PARSE_VERSION = 1

logging.basicConfig(level=logging.INFO)

# ── Supabase insert ───────────────────────────────────────────────
async def insert_alert(parsed: dict):
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=minimal",
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{SUPABASE_URL}/rest/v1/gpu_alerts",
            headers=headers,
            json=parsed,
        )
        if r.status_code >= 300:
            logging.error(f"[Supabase 오류] {r.status_code} {r.text}")

# ── 파싱 ──────────────────────────────────────────────────────────
def parse_alert(raw: str) -> dict:
    result = {
        "raw_message":   raw[:1000],
        "alert_type":    "unknown",
        "severity":      "INFO",
        "host":          None,
        "host_type":     None,
        "host_num":      None,
        "event_at":      None,
        "subsystem":     None,
        "error_code":    None,
        "metric_value":  None,
        "source_ip":     None,
        "parse_version": PARSE_VERSION,
        "parse_failed":  False,
    }

    # 1. Ping failure
    m = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - ([\w-]+) ping failure', raw)
    if m:
        result.update({"event_at": m.group(1), "host": m.group(2),
                       "alert_type": "ping_failure", "subsystem": "ping", "severity": "CRITICAL"})
        _set_host_meta(result); return result

    # 2. 수집 서버 연결
    if "수집 서버" in raw or "연결 중입니다" in raw:
        result.update({"alert_type": "log_collect", "subsystem": "collector", "severity": "INFO"})
        return result

    # 공통 헤더 파싱
    m = re.match(
        r'([\w-]+)\s*:\s*'
        r'((?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*(?:[+-]\d{2}:\d{2})?)|(?:\w+ +\d+ \d{2}:\d{2}:\d{2}))'
        r'\s+(?:[\w-]+\s+)?(.*)', raw, re.DOTALL)
    if not m:
        result["parse_failed"] = True; return result

    result["host"], result["event_at"], body = m.group(1), m.group(2), m.group(3)
    _set_host_meta(result)
    _fix_event_at(result)

    

    # 3. GPU 메모리 초과
    mm = re.search(r'ipmievd\[.*?\]: GPU Memory usage has exceeded (\d+)%', body)
    if mm:
        val = int(mm.group(1))
        result.update({"alert_type": "memory_exceeded", "subsystem": "ipmievd",
                       "error_code": "memory", "metric_value": val,
                       "severity": "CRITICAL" if val >= 95 else "WARNING"})
        return result

    # 9. IPMI 이벤트 (SEL Info, Power Supply 등)
    if "ipmievd" in body:
        result.update({"alert_type": "ipmi_event", "subsystem": "ipmievd",
                       "severity": "WARNING"})
        return result

    # 4. UFM Fabric
    if "UFM EVENT" in body or "IBPort" in body:
        result.update({"alert_type": "ufm_event", "subsystem": "ufm", "severity": "ERROR"})
        return result

    # 5. NVLink / Xid
    if "NVRM" in body or "knvlinkUpdate" in body:
        ec = "xid" if "Xid" in body else "knvlink"
        result.update({"alert_type": "nvlink_error", "subsystem": "kernel",
                       "error_code": ec, "severity": "CRITICAL" if ec == "xid" else "ERROR"})
        return result

    # 6. Kernel hung / Call Trace
    if "Call Trace" in body or "hung_task" in body:
        result.update({"alert_type": "kernel_hung", "subsystem": "kernel",
                       "error_code": "hung_task", "severity": "CRITICAL"})
        return result

    # 7. OOM (Out of Memory)
    if "Out of memory" in body or "oom-killer" in body or "oom_reaper" in body:
        result.update({"alert_type": "oom_kill", "subsystem": "kernel",
                       "error_code": "oom", "severity": "CRITICAL"})
        return result

    # 8. SSH 실패
    mm = re.search(r'sshd\[.*?\]: Failed password for (\S+) from ([\d.]+) port', body)
    if mm:
        result.update({"alert_type": "ssh_failure", "subsystem": "sshd",
                       "source_ip": mm.group(2), "severity": "WARNING"})
        return result

    # 9. SSH 연결 종료 (preauth)
    mm = re.search(r'sshd\[.*?\]: Connection closed by authenticating user (\S+) ([\d.]+) port', body)
    if mm:
        result.update({"alert_type": "ssh_failure", "subsystem": "sshd",
                       "source_ip": mm.group(2), "severity": "WARNING"})
        return result

    result["parse_failed"] = True
    return result


def _set_host_meta(r: dict):
    host = r.get("host") or ""
    if "gpu" in host:
        r["host_type"] = "gpu"
        m = re.search(r'gpu(\d+)', host)
        if m: r["host_num"] = int(m.group(1))
    elif "ops" in host:  r["host_type"] = "ops"
    elif "ufm" in host:  r["host_type"] = "ufm"
    elif "mgmt" in host: r["host_type"] = "mgmt"
    elif "pts" in host:  r["host_type"] = "pts"   # ← 추가
    elif "adm" in host:  r["host_type"] = "adm"   # ← 추가

def _fix_event_at(r: dict):
    """연도 없는 timestamp 보정"""
    if not r.get("event_at"):
        return
    try:
        datetime.fromisoformat(r["event_at"])
    except ValueError:
        try:
            parsed = datetime.strptime(r["event_at"].strip(), "%b %d %H:%M:%S")
            parsed = parsed.replace(year=datetime.now(KST).year)
            r["event_at"] = parsed.isoformat()
        except:
            r["event_at"] = None


# ── 핸들러 ────────────────────────────────────────────────────────
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.channel_post or update.message
    if not msg or not msg.text:
        return

    parsed = parse_alert(msg.text)
    parsed["received_at"] = datetime.now(KST).isoformat()

    try:
        await insert_alert(parsed)
        logging.info(f"[저장] {parsed['alert_type']} | {parsed['host']}")
    except Exception as e:
        logging.error(f"[오류] {e}")


# ── 실행 ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.ALL, handle_message))
    logging.info("봇 시작됨")
    app.run_polling()