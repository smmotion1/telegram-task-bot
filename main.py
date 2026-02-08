import hashlib
import hmac
import logging
import os
import re
import shlex
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from aiohttp import web
from dateutil import parser as date_parser
from dotenv import load_dotenv
from zoneinfo import ZoneInfo

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatMemberStatus, ParseMode
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler, filters
import random


DB_PATH = os.getenv("BOT_DB_PATH", "tasks.db")
TZ = ZoneInfo(os.getenv("BOT_TIMEZONE", "America/Los_Angeles"))
HTTP_PORT = int(os.getenv("PORT", "8000"))
MAILGUN_SIGNING_KEY = os.getenv("MAILGUN_SIGNING_KEY", "")
MAILGUN_ALLOWED_SENDER = os.getenv("MAILGUN_ALLOWED_SENDER", "fiverr.com")
GMAIL_WEBHOOK_TOKEN = os.getenv("GMAIL_WEBHOOK_TOKEN", "")


@dataclass
class Task:
    id: int
    title: str
    assignee: str
    deadline_utc: datetime
    creator_id: int
    chat_id: int
    thread_id: Optional[int]
    status: str


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                assignee TEXT NOT NULL,
                deadline_utc TEXT NOT NULL,
                creator_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                message_thread_id INTEGER,
                status TEXT NOT NULL DEFAULT 'assigned',
                created_at_utc TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS topics (
                chat_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                thread_id INTEGER NOT NULL,
                created_at_utc TEXT NOT NULL,
                UNIQUE(chat_id, name)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_assignments (
                chat_id INTEGER NOT NULL,
                task_id INTEGER NOT NULL,
                thread_id INTEGER,
                owner_id INTEGER NOT NULL,
                prompt_message_id INTEGER NOT NULL,
                created_at_utc TEXT NOT NULL,
                PRIMARY KEY (chat_id, task_id)
            )
            """
        )
        # Add message_thread_id column for existing DBs
        cols = [row["name"] for row in conn.execute("PRAGMA table_info(tasks)").fetchall()]
        if "message_thread_id" not in cols:
            conn.execute("ALTER TABLE tasks ADD COLUMN message_thread_id INTEGER")
        # Migrate legacy status values
        conn.execute("UPDATE tasks SET status = 'assigned' WHERE status = 'open'")


def parse_deadline(date_str: str, time_str: str) -> datetime:
    # Interpret as local timezone (PST/PDT from TZ setting)
    dt_local = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
    return dt_local.replace(tzinfo=TZ).astimezone(ZoneInfo("UTC"))


def format_deadline_local(deadline_utc: datetime) -> str:
    return deadline_utc.astimezone(TZ).strftime("%Y-%m-%d %H:%M %Z")


def deadline_from_row(row: sqlite3.Row) -> datetime:
    return datetime.fromisoformat(row["deadline_utc"]).astimezone(ZoneInfo("UTC"))


def task_from_row(row: sqlite3.Row) -> Task:
    return Task(
        id=row["id"],
        title=row["title"],
        assignee=row["assignee"],
        deadline_utc=deadline_from_row(row),
        creator_id=row["creator_id"],
        chat_id=row["chat_id"],
        thread_id=row["message_thread_id"],
        status=row["status"],
    )


def save_task(
    title: str,
    assignee: str,
    deadline_utc: datetime,
    creator_id: int,
    chat_id: int,
    thread_id: Optional[int],
) -> int:
    with get_db() as conn:
        cur = conn.execute(
            """
            INSERT INTO tasks (title, assignee, deadline_utc, creator_id, chat_id, message_thread_id, status, created_at_utc)
            VALUES (?, ?, ?, ?, ?, ?, 'assigned', ?)
            """,
            (
                title,
                assignee,
                deadline_utc.isoformat(),
                creator_id,
                chat_id,
                thread_id,
                datetime.now(tz=ZoneInfo("UTC")).isoformat(),
            ),
        )
        return int(cur.lastrowid)


def mark_task_done(task_id: int, chat_id: int) -> Optional[Task]:
    with get_db() as conn:
        cur = conn.execute(
            "SELECT * FROM tasks WHERE id = ? AND chat_id = ?",
            (task_id, chat_id),
        )
        row = cur.fetchone()
        if not row:
            return None
        conn.execute(
            "UPDATE tasks SET status = 'done' WHERE id = ? AND chat_id = ?",
            (task_id, chat_id),
        )
        return task_from_row(row)


def list_open_tasks(chat_id: int) -> list[Task]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM tasks WHERE chat_id = ? AND status != 'done' ORDER BY deadline_utc ASC",
            (chat_id,),
        ).fetchall()
        return [task_from_row(r) for r in rows]


def list_open_tasks_by_thread(chat_id: int, thread_id: Optional[int]) -> list[Task]:
    with get_db() as conn:
        if thread_id is None:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE chat_id = ? AND status != 'done' AND message_thread_id IS NULL ORDER BY deadline_utc ASC",
                (chat_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE chat_id = ? AND status != 'done' AND message_thread_id = ? ORDER BY deadline_utc ASC",
                (chat_id, thread_id),
            ).fetchall()
        return [task_from_row(r) for r in rows]


def find_tasks_by_title(chat_id: int, query: str) -> list[Task]:
    pattern = f"%{query}%"
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM tasks WHERE chat_id = ? AND status != 'done' AND title LIKE ? ORDER BY deadline_utc ASC",
            (chat_id, pattern),
        ).fetchall()
        return [task_from_row(r) for r in rows]


def get_task(task_id: int, chat_id: int) -> Optional[Task]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM tasks WHERE id = ? AND chat_id = ?",
            (task_id, chat_id),
        ).fetchone()
        return task_from_row(row) if row else None


async def is_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    if not update.effective_chat or not update.effective_user:
        return False
    member = await context.bot.get_chat_member(update.effective_chat.id, update.effective_user.id)
    return member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER)


def task_reminder_text(task: Task, when: str) -> str:
    return (
        f"⏰ Reminder {when}:\n"
        f"Task #{task.id}: {task.title}\n"
        f"Assignee: {task.assignee}\n"
        f"Deadline: {format_deadline_local(task.deadline_utc)}"
    )


def status_emoji(status: str) -> str:
    return {
        "assigned": "🟡",
        "in_progress": "🔵",
        "submitted": "🟣",
        "revision": "🟠",
        "sent_to_client": "🟢",
        "done": "✅",
        "blocked": "🔴",
    }.get(status, "🟡")


def status_label(status: str) -> str:
    return {
        "assigned": "Assigned",
        "in_progress": "In Progress",
        "submitted": "Submitted",
        "revision": "Revision",
        "sent_to_client": "Sent to Client",
        "done": "Done",
        "blocked": "Blocked",
    }.get(status, "Assigned")


def set_task_status(task_id: int, chat_id: int, status: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE tasks SET status = ? WHERE id = ? AND chat_id = ?",
            (status, task_id, chat_id),
        )

def set_task_assignee(task_id: int, chat_id: int, assignee: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE tasks SET assignee = ? WHERE id = ? AND chat_id = ?",
            (assignee, task_id, chat_id),
        )


def set_setting(key: str, value: str) -> None:
    with get_db() as conn:
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def get_setting(key: str) -> Optional[str]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT value FROM settings WHERE key = ?",
            (key,),
        ).fetchone()
        return row["value"] if row else None


def create_pending_assignment(
    chat_id: int,
    task_id: int,
    thread_id: Optional[int],
    owner_id: int,
    prompt_message_id: int,
) -> None:
    with get_db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO pending_assignments
            (chat_id, task_id, thread_id, owner_id, prompt_message_id, created_at_utc)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                chat_id,
                task_id,
                thread_id,
                owner_id,
                prompt_message_id,
                datetime.now(tz=ZoneInfo("UTC")).isoformat(),
            ),
        )


def get_pending_assignment_by_prompt(chat_id: int, prompt_message_id: int) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute(
            """
            SELECT * FROM pending_assignments
            WHERE chat_id = ? AND prompt_message_id = ?
            """,
            (chat_id, prompt_message_id),
        ).fetchone()


def clear_pending_assignment(chat_id: int, task_id: int) -> None:
    with get_db() as conn:
        conn.execute(
            "DELETE FROM pending_assignments WHERE chat_id = ? AND task_id = ?",
            (chat_id, task_id),
        )


def get_topic_thread_id(chat_id: int, name: str) -> Optional[int]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT thread_id FROM topics WHERE chat_id = ? AND name = ?",
            (chat_id, name.lower()),
        ).fetchone()
        return int(row["thread_id"]) if row else None


def save_topic(chat_id: int, name: str, thread_id: int) -> None:
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO topics (chat_id, name, thread_id, created_at_utc)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(chat_id, name) DO UPDATE SET thread_id = excluded.thread_id
            """,
            (
                chat_id,
                name.lower(),
                thread_id,
                datetime.now(tz=ZoneInfo("UTC")).isoformat(),
            ),
        )


def task_ack_keyboard(task_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("👍 All set", callback_data=f"task_ack:{task_id}:yes"),
                InlineKeyboardButton("❓ Need details", callback_data=f"task_ack:{task_id}:no"),
            ]
        ]
    )


def task_delivery_keyboard(task_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🟢 Send to Client", callback_data=f"task_delivery:{task_id}:sent"),
                InlineKeyboardButton("🟠 Request Revision", callback_data=f"task_delivery:{task_id}:revision"),
            ]
        ]
    )


async def send_assignee_prompt_to_chat(
    bot,
    chat_id: int,
    thread_id: Optional[int],
    task: Task,
) -> None:
    text = (
        f"📌 Task assigned, {task.assignee}.\n"
        "Ready to start, or need more details?"
    )
    await bot.send_message(
        chat_id=chat_id,
        text=text,
        reply_markup=task_ack_keyboard(task.id),
        message_thread_id=thread_id,
    )


async def schedule_task_jobs(application: Application, task: Task) -> None:
    # Schedule reminders 24h and 1h before deadline
    now_utc = datetime.now(tz=ZoneInfo("UTC"))
    offsets = [(timedelta(hours=24), "(24h)"), (timedelta(hours=1), "(1h)")]

    for offset, label in offsets:
        run_at = task.deadline_utc - offset
        if run_at <= now_utc:
            continue
        job_name = f"task:{task.id}:{int(offset.total_seconds())}"
        application.job_queue.run_once(
            remind_task_job,
            when=run_at,
            data={
                "task_id": task.id,
                "chat_id": task.chat_id,
                "thread_id": task.thread_id,
                "label": label,
            },
            name=job_name,
        )


def cancel_task_jobs(application: Application, task_id: int) -> None:
    for job in application.job_queue.jobs():
        if job.name and job.name.startswith(f"task:{task_id}:"):
            job.schedule_removal()


async def remind_task_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    data = context.job.data
    task_id = data["task_id"]
    chat_id = data["chat_id"]
    thread_id = data.get("thread_id")
    label = data["label"]

    task = get_task(task_id, chat_id)
    if not task or task.status == "done":
        return

    await context.bot.send_message(
        chat_id=chat_id,
        message_thread_id=thread_id,
        text=task_reminder_text(task, label),
    )


def build_daily_update_message(tasks: list[Task]) -> str:
    if not tasks:
        return "🧾 Daily update (10 PM PST)\n\n📭 No open tasks right now."

    lines = []
    for t in tasks:
        due = t.deadline_utc.astimezone(TZ).strftime("%b %d, %H:%M")
        assignee = t.assignee if t.assignee != "@unassigned" else "Unassigned"
        lines.append(
            f"{status_emoji(t.status)} #{t.id} — {t.title}\n"
            f"   👤 {assignee} | ⏰ {due}"
        )
    return "🧾 Daily update (10 PM PST)\n\n" + "\n\n".join(lines)


async def daily_update_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = get_setting("general_chat_id")
    thread_id = get_setting("general_thread_id")
    if not chat_id:
        return
    tasks = list_open_tasks(int(chat_id))
    text = build_daily_update_message(tasks)
    await context.bot.send_message(
        chat_id=int(chat_id),
        message_thread_id=int(thread_id) if thread_id else None,
        text=text,
    )


def verify_mailgun_signature(timestamp: str, token: str, signature: str) -> bool:
    if not MAILGUN_SIGNING_KEY:
        return False
    msg = f"{timestamp}{token}".encode("utf-8")
    digest = hmac.new(MAILGUN_SIGNING_KEY.encode("utf-8"), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, signature)


def extract_client_name(subject: str, body: str) -> Optional[str]:
    patterns = [
        r"(?i)order from[:\-]\s*(.+)",
        r"(?i)you received an order from\s+(.+)",
        r"(?i)you just received an order from\s+(.+)",
        r"(?i)buyer[:\-]\s*(.+)",
        r"(?i)client[:\-]\s*(.+)",
        r"(?i)from[:\-]\s*(.+)",
    ]
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        for pat in patterns:
            m = re.search(pat, line)
            if m:
                name = m.group(1).strip()
                name = re.sub(r"[!.:\s]+$", "", name)
                return name
    m = re.search(r"(?i)from\s+(.+)", subject or "")
    if m:
        name = m.group(1).strip()
        name = re.sub(r"[!.:\s]+$", "", name)
        return name
    return None


def extract_due_datetime(body: str, subject: str) -> Optional[datetime]:
    candidate_lines = []
    for line in body.splitlines():
        if re.search(r"(?i)due|deliver|delivery|deadline", line):
            candidate_lines.append(line)
    candidate_lines.extend([subject])
    now_local = datetime.now(tz=TZ).replace(hour=18, minute=0, second=0, microsecond=0)
    for line in candidate_lines:
        try:
            dt = date_parser.parse(line, fuzzy=True, default=now_local)
        except (ValueError, TypeError):
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=TZ)
        return dt
    return None


def extract_order_id(text: str) -> Optional[str]:
    m = re.search(r"#([A-Za-z0-9]{6,})", text)
    return m.group(1) if m else None


async def ensure_topic(application: Application, chat_id: int, client_name: str) -> Optional[int]:
    existing = get_topic_thread_id(chat_id, client_name)
    if existing:
        return existing
    try:
        topic = await application.bot.create_forum_topic(chat_id=chat_id, name=client_name)
        save_topic(chat_id, client_name, topic.message_thread_id)
        return topic.message_thread_id
    except Exception as exc:
        logging.warning("Failed to create topic: %s", exc)
        return None


async def handle_mailgun_inbound(request: web.Request, application: Application) -> web.Response:
    data = await request.post()
    timestamp = data.get("timestamp", "")
    token = data.get("token", "")
    signature = data.get("signature", "")
    if not verify_mailgun_signature(timestamp, token, signature):
        return web.Response(status=403, text="invalid signature")

    sender = (data.get("sender") or "").lower()
    if MAILGUN_ALLOWED_SENDER and MAILGUN_ALLOWED_SENDER.lower() not in sender:
        return web.Response(status=200, text="ignored")

    subject = data.get("subject", "") or ""
    body = data.get("stripped-text", "") or data.get("body-plain", "") or ""
    await process_inbound_order(application, subject, body, source="Mailgun")
    return web.Response(status=200, text="ok")


async def process_inbound_order(application: Application, subject: str, body: str, source: str) -> None:
    chat_id = get_setting("general_chat_id")
    if not chat_id:
        return
    chat_id_int = int(chat_id)

    owner_id = get_setting("owner_user_id")
    owner_username = get_setting("owner_username") or "@smbath7"
    if not owner_id:
        await application.bot.send_message(
            chat_id=chat_id_int,
            text=f"⚠️ {source} order received, but owner is not set.\n"
                 "Run /task setowner.",
        )
        return

    client_name = extract_client_name(subject, body) or "Fiverr Client"
    due = extract_due_datetime(body, subject)
    if not due:
        await application.bot.send_message(
            chat_id=chat_id_int,
            text=f"⚠️ {source} order received, but I couldn't parse the due date.\n"
                 "Please create the task manually.",
        )
        return

    deadline_local = (due - timedelta(days=1)).astimezone(TZ)
    deadline_utc = deadline_local.astimezone(ZoneInfo("UTC"))

    order_id = extract_order_id(subject + "\n" + body)
    title = f"Fiverr order #{order_id}" if order_id else f"Fiverr order — {client_name}"

    thread_id = await ensure_topic(application, chat_id_int, client_name)

    task_id = save_task(
        title=title,
        assignee="@unassigned",
        deadline_utc=deadline_utc,
        creator_id=int(owner_id),
        chat_id=chat_id_int,
        thread_id=thread_id,
    )

    task = get_task(task_id, chat_id_int)
    if task:
        await schedule_task_jobs(application, task)
        await application.bot.send_message(
            chat_id=chat_id_int,
            message_thread_id=thread_id,
            text=f"🟡 Task #{task_id} created from {source}.\n"
                 f"👤 Unassigned | ⏰ {format_deadline_local(task.deadline_utc)}",
        )
        prompt = await application.bot.send_message(
            chat_id=chat_id_int,
            message_thread_id=thread_id,
            text=f"{owner_username}, who should be assigned? Reply with @username.",
        )
        create_pending_assignment(
            chat_id=chat_id_int,
            task_id=task_id,
            thread_id=thread_id,
            owner_id=int(owner_id),
            prompt_message_id=prompt.message_id,
        )


async def handle_gmail_webhook(request: web.Request, application: Application) -> web.Response:
    if not GMAIL_WEBHOOK_TOKEN:
        return web.Response(status=403, text="missing token")
    token = request.headers.get("X-Webhook-Token") or request.query.get("token", "")
    if token != GMAIL_WEBHOOK_TOKEN:
        return web.Response(status=403, text="invalid token")

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    subject = payload.get("subject", "") or ""
    body = payload.get("body", "") or payload.get("text", "") or ""
    await process_inbound_order(application, subject, body, source="Gmail")
    return web.Response(status=200, text="ok")


async def start_webserver(application: Application) -> None:
    web_app = web.Application()
    web_app.router.add_post("/mailgun/inbound", lambda request: handle_mailgun_inbound(request, application))
    web_app.router.add_post("/gmail/inbound", lambda request: handle_gmail_webhook(request, application))
    runner = web.AppRunner(web_app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", HTTP_PORT)
    await site.start()
    application.bot_data["web_runner"] = runner


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Task bot is running. Use /task help for commands."
    )

async def cmd_approve(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    messages = [
        "🎉 Approved! Great work! ✅",
        "👏 Congrats! Approved and ready to go! 🚀",
        "✅ Approved! Fantastic job! ✨",
        "🥳 Awesome! Approved! Let’s ship it! 🚢",
        "💯 Approved! You nailed it! 🔥",
    ]
    await update.message.reply_text(random.choice(messages))


async def cmd_task(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.effective_chat:
        return

    args = update.message.text.split(maxsplit=1)
    if len(args) == 1:
        await update.message.reply_text("ℹ️ Usage: /task help")
        return

    sub = args[1].strip()
    if sub.startswith("help"):
        await update.message.reply_text(
            "Commands:\n"
            "/task add \"Title\" @user YYYY-MM-DD HH:MM\n"
            "/task list\n"
            "/task listall\n"
            "/task view <id>\n"
            "/task done <id>\n"
            "/task submit <id>\n"
            "/task find \"keyword\"\n"
            "/task status\n"
            "/task setgeneral\n"
            "/task setassignee @user\n"
            "/task setowner\n"
        )
        return

    if sub.startswith("add"):
        if not await is_admin(update, context):
            await update.message.reply_text("🛡️ Only admins can create tasks.")
            return

        try:
            # Use shlex to preserve quoted title
            parts = shlex.split(sub)
            # parts[0] == 'add'
            title = parts[1]
            assignee = parts[2]
            date_str = parts[3]
            time_str = parts[4]
        except Exception:
            await update.message.reply_text("⚠️ Format: /task add \"Title\" @user YYYY-MM-DD HH:MM")
            return

        if not assignee.startswith("@"): 
            await update.message.reply_text("⚠️ Assignee must be a @username.")
            return

        try:
            deadline_utc = parse_deadline(date_str, time_str)
        except ValueError:
            await update.message.reply_text("⏱️ Invalid date/time. Use YYYY-MM-DD HH:MM")
            return

        task_id = save_task(
            title=title,
            assignee=assignee,
            deadline_utc=deadline_utc,
            creator_id=update.effective_user.id,
            chat_id=update.effective_chat.id,
            thread_id=update.effective_message.message_thread_id
            if update.effective_message
            else None,
        )

        task = get_task(task_id, update.effective_chat.id)
        if task:
            await schedule_task_jobs(context.application, task)
            await send_assignee_prompt_to_chat(
                context.bot,
                update.effective_chat.id,
                task.thread_id,
                task,
            )

        await update.message.reply_text(
            f"🟡 Task #{task_id} created. Deadline {format_deadline_local(deadline_utc)}"
        )
        return

    if sub.startswith("list"):
        # /task list => current topic only, /task listall => all
        if sub.startswith("listall"):
            tasks = list_open_tasks(update.effective_chat.id)
        else:
            thread_id = update.effective_message.message_thread_id if update.effective_message else None
            tasks = list_open_tasks_by_thread(update.effective_chat.id, thread_id)
        if not tasks:
            await update.message.reply_text("📭 No open tasks.")
            return

        if sub.startswith("listall"):
            lines = [
                f"{status_emoji(t.status)} #{t.id} — {t.title} ({status_label(t.status)})"
                for t in tasks
            ]
            await update.message.reply_text("🗂 All open tasks:\n" + "\n".join(lines))
        else:
            lines = [
                f"{status_emoji(t.status)} #{t.id} — {t.title} (Due: {t.deadline_utc.astimezone(TZ).strftime('%b %d')})"
                for t in tasks
            ]
            await update.message.reply_text("📋 Open tasks in this topic:\n" + "\n".join(lines))
        return

    if sub.startswith("find"):
        try:
            parts = shlex.split(sub)
            query = parts[1]
        except Exception:
            await update.message.reply_text("ℹ️ Usage: /task find \"keyword\"")
            return
        tasks = find_tasks_by_title(update.effective_chat.id, query)
        if not tasks:
            await update.message.reply_text("🔍 No matching open tasks.")
            return
        lines = [
            f"{status_emoji(t.status)} #{t.id} — {t.title} ({status_label(t.status)})"
            for t in tasks
        ]
        await update.message.reply_text("Matches:\n" + "\n".join(lines))
        return

    if sub.startswith("view"):
        try:
            task_id = int(sub.split()[1])
        except Exception:
            await update.message.reply_text("ℹ️ Usage: /task view <id>")
            return
        task = get_task(task_id, update.effective_chat.id)
        if not task:
            await update.message.reply_text("❌ Task not found.")
            return
        assignee = task.assignee if task.assignee != "@unassigned" else "Unassigned"
        await update.message.reply_text(
            f"Task #{task.id}\n"
            f"Title: {task.title}\n"
            f"Assignee: {assignee}\n"
            f"Deadline: {format_deadline_local(task.deadline_utc)}\n"
            f"Status: {status_emoji(task.status)} {status_label(task.status)}"
        )
        return

    if sub.startswith("done"):
        if not await is_admin(update, context):
            await update.message.reply_text("🛡️ Only admins can close tasks.")
            return
        try:
            task_id = int(sub.split()[1])
        except Exception:
            await update.message.reply_text("ℹ️ Usage: /task done <id>")
            return
        task = mark_task_done(task_id, update.effective_chat.id)
        if not task:
            await update.message.reply_text("❌ Task not found.")
            return
        cancel_task_jobs(context.application, task_id)
        await update.message.reply_text("✅ Task completed.\nGreat work 👏")
        return

    if sub.startswith("submit"):
        if not update.effective_user:
            return
        try:
            task_id = int(sub.split()[1])
        except Exception:
            await update.message.reply_text("ℹ️ Usage: /task submit <id>")
            return
        task = get_task(task_id, update.effective_chat.id)
        if not task:
            await update.message.reply_text("❌ Task not found.")
            return
        if task.assignee == "@unassigned":
            await update.message.reply_text("⚠️ This task is not assigned yet.")
            return
        assignee_username = task.assignee.lstrip("@").lower()
        if (update.effective_user.username or "").lower() != assignee_username:
            await update.message.reply_text("🧑‍💻 Only the assignee can submit this task.")
            return
        await update.message.reply_text(
            "🟣 Task submitted.\nChoose next step:",
            reply_markup=task_delivery_keyboard(task.id),
            message_thread_id=task.thread_id,
        )
        set_task_status(task.id, update.effective_chat.id, "submitted")
        return

    if sub.startswith("status"):
        await update.message.reply_text(
            "🟡 Assigned | 🔵 In Progress | 🟣 Submitted\n"
            "🟠 Revision | 🟢 Sent to Client | ✅ Done | 🔴 Blocked"
        )
        return

    if sub.startswith("setgeneral"):
        if not await is_admin(update, context):
            await update.message.reply_text("🛡️ Only admins can set the General topic.")
            return
        thread_id = update.effective_message.message_thread_id if update.effective_message else None
        set_setting("general_chat_id", str(update.effective_chat.id))
        if thread_id is None:
            set_setting("general_thread_id", "")
            await update.message.reply_text("✅ Daily updates will be posted in the main chat.")
        else:
            set_setting("general_thread_id", str(thread_id))
            await update.message.reply_text("✅ General topic set for daily updates.")
        return

    if sub.startswith("setassignee"):
        if not await is_admin(update, context):
            await update.message.reply_text("🛡️ Only admins can set the default assignee.")
            return
        try:
            parts = shlex.split(sub)
            assignee = parts[1]
        except Exception:
            await update.message.reply_text("ℹ️ Usage: /task setassignee @user")
            return
        if not assignee.startswith("@"):
            await update.message.reply_text("⚠️ Assignee must be a @username.")
            return
        set_setting("default_assignee", assignee)
        await update.message.reply_text(f"✅ Default assignee set to {assignee}")
        return

    if sub.startswith("setowner"):
        if not await is_admin(update, context):
            await update.message.reply_text("🛡️ Only admins can set the owner.")
            return
        if not update.effective_user:
            return
        set_setting("owner_user_id", str(update.effective_user.id))
        if update.effective_user.username:
            set_setting("owner_username", f"@{update.effective_user.username}")
        await update.message.reply_text("✅ Owner set for automated tasks.")
        return

    await update.message.reply_text("❓ Unknown subcommand. Use /task help.")


async def on_callback_query(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.callback_query or not update.effective_user:
        return
    query = update.callback_query
    data = query.data or ""
    if data.startswith("task_ack:"):
        try:
            _, task_id_str, choice = data.split(":", 2)
            task_id = int(task_id_str)
        except Exception:
            await query.answer("⚠️ Invalid action.", show_alert=True)
            return

        task = get_task(task_id, query.message.chat_id if query.message else 0)
        if not task:
            await query.answer("❌ Task not found.", show_alert=True)
            return

        # Ensure only the assignee can answer
        assignee_username = task.assignee.lstrip("@").lower()
        if (update.effective_user.username or "").lower() != assignee_username:
            await query.answer("🧑‍💻 Only the assignee can respond.", show_alert=True)
            return

        await query.answer()
        await query.edit_message_reply_markup(reply_markup=None)

        if choice == "yes":
            set_task_status(task.id, task.chat_id, "in_progress")
            await query.message.reply_text("🔵 Task in progress.\nGood luck 🚀")
            return

        if choice == "no":
            set_task_status(task.id, task.chat_id, "blocked")
            creator_mention = f'<a href="tg://user?id={task.creator_id}">task creator</a>'
            await query.message.reply_text(
                f"🔴 Task blocked.\nWaiting for more details from {creator_mention} 🤔",
                parse_mode=ParseMode.HTML,
            )
            return

        return

    if data.startswith("task_delivery:"):
        try:
            _, task_id_str, choice = data.split(":", 2)
            task_id = int(task_id_str)
        except Exception:
            await query.answer("⚠️ Invalid action.", show_alert=True)
            return

        task = get_task(task_id, query.message.chat_id if query.message else 0)
        if not task:
            await query.answer("❌ Task not found.", show_alert=True)
            return

        if update.effective_user.id != task.creator_id:
            await query.answer("🛡️ Only the task creator can choose this.", show_alert=True)
            return

        await query.answer()
        await query.edit_message_reply_markup(reply_markup=None)

        if choice == "sent":
            set_task_status(task.id, task.chat_id, "sent_to_client")
            await query.message.reply_text(
                f"🟢 Sent to client.\n{task.assignee} Fingers crossed 🤞"
            )
            return

        if choice == "revision":
            set_task_status(task.id, task.chat_id, "revision")
            creator_mention = f'<a href="tg://user?id={task.creator_id}">task creator</a>'
            await query.message.reply_text(
                f"🟠 Revision requested.\n{creator_mention} please add feedback 📝",
                parse_mode=ParseMode.HTML,
            )
            return

        return


async def on_reply_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not update.message or not update.effective_chat or not update.effective_user:
        return
    reply_to = update.message.reply_to_message
    if not reply_to:
        return
    pending = get_pending_assignment_by_prompt(update.effective_chat.id, reply_to.message_id)
    if not pending:
        return
    if update.effective_user.id != pending["owner_id"]:
        return

    match = re.search(r"@([A-Za-z0-9_]{5,})", update.message.text or "")
    if not match:
        await update.message.reply_text("⚠️ Please reply with a valid @username.")
        return
    assignee = f"@{match.group(1)}"

    set_task_assignee(pending["task_id"], update.effective_chat.id, assignee)
    clear_pending_assignment(update.effective_chat.id, pending["task_id"])

    task = get_task(pending["task_id"], update.effective_chat.id)
    if not task:
        await update.message.reply_text("❌ Task not found.")
        return

    await update.message.reply_text(
        f"✅ Assigned to {assignee}.",
        message_thread_id=pending["thread_id"],
    )
    await send_assignee_prompt_to_chat(
        context.bot,
        update.effective_chat.id,
        pending["thread_id"],
        task,
    )


async def on_startup(app: Application) -> None:
    # Reschedule reminders for existing open tasks
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM tasks WHERE status != 'done'"
        ).fetchall()
        for row in rows:
            task = task_from_row(row)
            await schedule_task_jobs(app, task)

    # Daily update at 10 PM PST/PDT
    daily_time = datetime.now(tz=TZ).replace(hour=22, minute=0, second=0, microsecond=0).time()
    app.job_queue.run_daily(
        daily_update_job,
        time=daily_time,
        name="daily_update_10pm",
    )

    await start_webserver(app)


def main() -> None:
    load_dotenv()
    setup_logging()
    init_db()

    token = os.getenv("BOT_TOKEN")
    if not token:
        raise SystemExit("BOT_TOKEN is not set. Put it in .env")

    application = Application.builder().token(token).build()
    if application.job_queue is None:
        raise SystemExit(
            "JobQueue is not available. Reinstall dependencies with "
            "`pip install -r requirements.txt` to enable reminders."
        )

    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("task", cmd_task))
    application.add_handler(CommandHandler("approve", cmd_approve))
    application.add_handler(CallbackQueryHandler(on_callback_query))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_reply_message))

    application.post_init = on_startup

    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
