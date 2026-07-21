from __future__ import annotations

import html
import io
from datetime import datetime

from aiogram import Bot, Dispatcher, F, Router
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

from .config import Settings
from .services import ProtectionService


def _home_keyboard(settings: Settings) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    external: list[InlineKeyboardButton] = []
    if settings.updates_url:
        external.append(InlineKeyboardButton(text="📢 Updates", url=settings.updates_url))
    if settings.support_url:
        external.append(InlineKeyboardButton(text="💬 Support", url=settings.support_url))
    if external:
        rows.append(external)
    rows.extend(
        [
            [InlineKeyboardButton(text="🏢 Dashboard", callback_data="dashboard")],
            [
                InlineKeyboardButton(text="ℹ️ Help", callback_data="help"),
                InlineKeyboardButton(text="👨‍💻 About", callback_data="about"),
            ],
        ]
    )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def _dashboard_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="🌐 Sites", callback_data="sites"),
                InlineKeyboardButton(text="📊 Statistics", callback_data="stats"),
            ],
            [
                InlineKeyboardButton(text="🛡 Security", callback_data="security"),
                InlineKeyboardButton(text="🕰 History", callback_data="history"),
            ],
            [
                InlineKeyboardButton(text="📋 Logs", callback_data="logs"),
                InlineKeyboardButton(text="⚙️ Settings", callback_data="settings"),
            ],
            [InlineKeyboardButton(text="🏡 Home", callback_data="home")],
        ]
    )


def _back_keyboard(target: str = "dashboard") -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="⬅️ Back", callback_data=target)]]
    )


def _home_text(settings: Settings, name: str = "") -> str:
    safe_name = html.escape(name or "there")
    return (
        f"👋 <b>Hello {safe_name}</b>\n\n"
        f"🚀 Welcome to <b>{html.escape(settings.app_name)}</b>\n\n"
        "🔐 Secure shortened links and block direct-paste or shared callback attempts.\n\n"
        "✨ <b>Core features</b>\n"
        "🛡 Same-browser session protection\n"
        "⚡ One-time callback and replay blocking\n"
        "👨‍💻 Developer API\n"
        "📊 Statistics and security logs"
    )


def _dashboard_text() -> str:
    return (
        "🏢 <b>Dashboard</b>\n\n"
        "🛠 Manage your links and protection system.\n\n"
        "🌐 Manage configured shortener\n"
        "📊 View statistics and performance\n"
        "📂 Track access and bypass activity\n"
        "👨‍💻 Create links with /protect or the API"
    )


async def _edit(query: CallbackQuery, text: str, keyboard: InlineKeyboardMarkup) -> None:
    if not query.message:
        return
    if query.message.photo:
        await query.message.edit_caption(caption=text, reply_markup=keyboard, parse_mode=ParseMode.HTML)
    else:
        await query.message.edit_text(text, reply_markup=keyboard, parse_mode=ParseMode.HTML)


def create_bot_components(
    settings: Settings, service: ProtectionService
) -> tuple[Bot, Dispatcher]:
    bot = Bot(settings.bot_token)
    dispatcher = Dispatcher()
    router = Router()

    def is_admin(user_id: int | None) -> bool:
        return bool(user_id and user_id in settings.bot_admin_ids)

    @router.message(CommandStart())
    async def start(message: Message) -> None:
        name = message.from_user.first_name if message.from_user else ""
        text = _home_text(settings, name)
        if settings.bot_banner_url:
            await message.answer_photo(
                settings.bot_banner_url,
                caption=text,
                reply_markup=_home_keyboard(settings),
                parse_mode=ParseMode.HTML,
            )
        else:
            await message.answer(text, reply_markup=_home_keyboard(settings), parse_mode=ParseMode.HTML)

    @router.message(Command("protect"))
    async def protect(message: Message) -> None:
        user_id = message.from_user.id if message.from_user else None
        if not is_admin(user_id):
            await message.answer("⛔ This command is restricted to configured administrators.")
            return
        _, _, raw_url = (message.text or "").partition(" ")
        raw_url = raw_url.strip()
        if not raw_url:
            await message.answer("Usage: <code>/protect https://example.com/target</code>", parse_mode=ParseMode.HTML)
            return
        try:
            link = await service.create_link(raw_url, user_id=user_id)
        except ValueError as exc:
            await message.answer(f"❌ {html.escape(str(exc))}")
            return
        await message.answer(
            "✅ <b>Protected link created</b>\n\n"
            f"<code>{html.escape(link['protected_url'])}</code>\n\n"
            "This URL starts the same-browser security flow.",
            parse_mode=ParseMode.HTML,
        )

    @router.message(Command("stats"))
    async def stats_command(message: Message) -> None:
        if not is_admin(message.from_user.id if message.from_user else None):
            return
        stats = await service.store.stats()
        await message.answer(_stats_text(stats), parse_mode=ParseMode.HTML)

    @router.message(Command("logs"))
    async def logs_command(message: Message) -> None:
        if not is_admin(message.from_user.id if message.from_user else None):
            return
        await _send_logs(message, service)

    @router.callback_query(F.data == "home")
    async def home(query: CallbackQuery) -> None:
        name = query.from_user.first_name if query.from_user else ""
        await _edit(query, _home_text(settings, name), _home_keyboard(settings))
        await query.answer()

    @router.callback_query(F.data == "dashboard")
    async def dashboard(query: CallbackQuery) -> None:
        if not is_admin(query.from_user.id):
            await query.answer("Administrator access required", show_alert=True)
            return
        await _edit(query, _dashboard_text(), _dashboard_keyboard())
        await query.answer()

    @router.callback_query(F.data == "stats")
    async def stats_callback(query: CallbackQuery) -> None:
        stats = await service.store.stats()
        await _edit(query, _stats_text(stats), _back_keyboard())
        await query.answer()

    @router.callback_query(F.data == "sites")
    async def sites(query: CallbackQuery) -> None:
        domain = settings.shortener_domain or "Demo/direct mode"
        mode = "Demo" if settings.demo_mode else "Production API"
        text = (
            "🌐 <b>Sites Manager</b>\n\n"
            f"🔗 Provider: <b>{html.escape(settings.shortener_name)}</b>\n"
            f"🌍 Domain: <code>{html.escape(domain)}</code>\n"
            f"⚙️ Mode: <b>{mode}</b>\n\n"
            "Provider credentials are managed safely through environment variables."
        )
        await _edit(query, text, _back_keyboard())
        await query.answer()

    @router.callback_query(F.data == "security")
    async def security(query: CallbackQuery) -> None:
        text = (
            "🛡 <b>Security</b>\n\n"
            "✅ Signed same-browser session\n"
            "✅ One-time nonce\n"
            "✅ Expiry and replay protection\n"
            "✅ Browser binding\n"
            f"{'✅' if settings.bind_ip_prefix else '➖'} Network-prefix binding\n"
            f"{'✅' if settings.strict_referrer else '➖'} Strict shortener referrer"
        )
        await _edit(query, text, _back_keyboard())
        await query.answer()

    @router.callback_query(F.data == "history")
    async def history(query: CallbackQuery) -> None:
        events = await service.store.list_events(10)
        lines = ["🕰 <b>Recent Activity</b>", ""]
        for event in events:
            icon = "✅" if event["type"] == "access_granted" else "⛔" if event["type"] == "access_denied" else "🔹"
            reason = f" ({event['reason']})" if event.get("reason") else ""
            lines.append(f"{icon} {html.escape(event['type'])}{html.escape(reason)}")
        if not events:
            lines.append("No activity recorded yet.")
        await _edit(query, "\n".join(lines), _back_keyboard())
        await query.answer()

    @router.callback_query(F.data == "logs")
    async def logs(query: CallbackQuery) -> None:
        if query.message:
            await _send_logs(query.message, service)
        await query.answer("Log export created")

    @router.callback_query(F.data == "settings")
    async def settings_callback(query: CallbackQuery) -> None:
        text = (
            "⚙️ <b>Settings</b>\n\n"
            f"⏳ Default link expiry: <b>{settings.link_expiry_seconds // 3600} hours</b>\n"
            f"🕐 Flow expiry: <b>{settings.flow_ttl_seconds // 60} minutes</b>\n"
            f"⚡ Minimum completion time: <b>{settings.min_completion_seconds} seconds</b>\n"
            f"🧪 Demo mode: <b>{'ON' if settings.demo_mode else 'OFF'}</b>"
        )
        await _edit(query, text, _back_keyboard())
        await query.answer()

    @router.callback_query(F.data == "help")
    async def help_callback(query: CallbackQuery) -> None:
        text = (
            "ℹ️ <b>Help</b>\n\n"
            "Admin command:\n"
            "<code>/protect TARGET_URL</code> — create a protected link\n"
            "<code>/stats</code> — system statistics\n"
            "<code>/logs</code> — export recent activity\n\n"
            "For integrations use <code>POST /api/v1/links</code>."
        )
        await _edit(query, text, _back_keyboard("home"))
        await query.answer()

    @router.callback_query(F.data == "about")
    async def about(query: CallbackQuery) -> None:
        text = (
            f"🤖 <b>{html.escape(settings.app_name)}</b>\n\n"
            "🚀 Version: 1.0\n"
            "🐍 Language: Python 3\n"
            "☁️ Deploy: Koyeb or Vercel\n"
            f"👨‍💻 Owner: {html.escape(settings.owner_username)}"
        )
        await _edit(query, text, _back_keyboard("home"))
        await query.answer()

    dispatcher.include_router(router)
    return bot, dispatcher


def _stats_text(stats: dict[str, int]) -> str:
    return (
        "📊 <b>System Statistics</b>\n\n"
        f"🔗 Links created: <b>{stats['links_created']}</b>\n"
        f"✅ Successful access: <b>{stats['successful_access']}</b>\n"
        f"⛔ Failed/blocked: <b>{stats['blocked_access']}</b>\n"
        f"🔄 Active flows: <b>{stats['active_flows']}</b>\n"
        f"📋 Logged events: <b>{stats['events']}</b>"
    )


async def _send_logs(message: Message, service: ProtectionService) -> None:
    events = await service.store.list_events(100)
    stream = io.StringIO()
    stream.write("RDX ANTI-BYPASS SYSTEM LOG\n")
    stream.write("=" * 60 + "\n")
    for event in reversed(events):
        created = event.get("created_at")
        stamp = created.isoformat() if isinstance(created, datetime) else str(created)
        stream.write(
            f"{stamp} | {event.get('type')} | link={event.get('link_id')} "
            f"| reason={event.get('reason')}\n"
        )
    payload = stream.getvalue().encode()
    await message.answer_document(
        BufferedInputFile(payload, filename="rdx_anti_bypass_logs.txt"),
        caption="📄 Detailed security log report",
    )
