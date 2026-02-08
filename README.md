# Telegram Task Bot

A lightweight Telegram group bot for task creation, assignment, and deadline reminders.

## Features
- Create tasks with deadlines and assignees
- List and view tasks
- Mark tasks done
- Automatic reminders 24h and 1h before deadline
- Admin-only task creation and closure

## Setup
1. Create a Telegram bot with BotFather and get the token.
2. Copy `.env.example` to `.env` and set `BOT_TOKEN`.
3. Install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

4. Run the bot:

```bash
python main.py
```

5. Add the bot to your group and make it an admin (required to read admin status).

## Mailgun Inbound (Optional)
- Set these in `.env`:
  - `MAILGUN_SIGNING_KEY` (from Mailgun)
  - `MAILGUN_ALLOWED_SENDER` (default `fiverr.com`)
  - `PORT` (default `8000`)
- Run in your group:
  - `/task setgeneral` in the main chat or General topic
  - `/task setowner` (admin only)
  - `/task setassignee @user` (admin only)

## Commands
- `/task add "Title" @user YYYY-MM-DD HH:MM`
- `/task list`
- `/task view <id>`
- `/task done <id>`
- `/task submit <id>`
- `/task status`
- `/approve`

## Notes
- Deadlines are interpreted in the timezone set by `BOT_TIMEZONE` (default: `America/Los_Angeles`).
- Reminders are sent 24 hours and 1 hour before the deadline.
- Tasks are stored in `tasks.db` (SQLite) for persistence.
