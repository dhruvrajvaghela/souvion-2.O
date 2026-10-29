"""
SOUVION SECURITY — single-file Discord bot (Python 3.12, discord.py 2.x)

Install dependency:  pip install -U discord.py
Run locally:         python souvion_security_single.py
Required env var:    DISCORD_TOKEN (BOT_TOKEN is accepted as a fallback)
Optional env vars:   OWNER_IDS, DATA_DIR, LOG_LEVEL
Railway:              Set DISCORD_TOKEN in Variables; mount a Volume at /data
                      and set DATA_DIR=/data. Start command: python souvion_security_single.py
Discord Developer Portal: enable Server Members Intent and Message Content Intent.
Invite only the permissions this bot needs; avoid Administrator unless deliberately required.
Test in a private server before using on a production server.

Security note: this is not a verified Wick replacement. Discord API behavior, permissions,
audit-log delays and rate limits mean protections must be live-tested in a private server.
"""
import os, re, json, time, copy, asyncio, logging, tempfile
import datetime as dt
from pathlib import Path
from collections import defaultdict, deque
from zoneinfo import ZoneInfo

# Built-in pure security-policy helpers (merged from security_core.py).
def prune_window(events, now: float, seconds: float) -> int:
    """Remove timestamps older than `seconds`; return the remaining event count."""
    while events and now - events[0] > seconds:
        events.popleft()
    return len(events)

def dangerous_permission_escalation(before_bits: int, after_bits: int, dangerous_bits: int) -> bool:
    """True when a previously absent dangerous permission bit was added."""
    added_bits = after_bits & ~before_bits
    return bool(added_bits & dangerous_bits)

def should_auto_enable_raidmode(enabled: bool, recent_joins: int, threshold: int) -> bool:
    """Require a threshold-sized join spike and avoid re-triggering while enabled."""
    return not enabled and threshold > 0 and recent_joins >= threshold

import discord
from discord.ext import commands, tasks

TOKEN = os.getenv("DISCORD_TOKEN") or os.getenv("BOT_TOKEN")
OWNER_IDS = {int(x) for x in os.getenv("OWNER_IDS", "").split(",") if x.strip().isdigit()}
DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATA_FILE = DATA_DIR / "souvion_data.json"
TZ = ZoneInfo("Asia/Kolkata")
COLOR = 0x5865F2
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("souvion")

# ───────────────────────── storage ─────────────────────────
DEFAULTS = {
    "prefix": "!",
    "antinuke": {
        "enabled": False, "whitelist": [], "punishment": "ban",
        "thresholds": {  # action: [limit, seconds]
            "channel_delete": [2, 10], "channel_create": [3, 10], "channel_update": [3, 10],
            "role_delete": [2, 10], "role_create": [3, 10], "role_update": [2, 10],
            "ban": [3, 10], "kick": [3, 10], "webhook": [2, 10],
        },
    },
    "superantinuke": {"enabled": False, "whitelist": [], "burst": [3, 10],
                      "bot_add": "kick_bot_and_punish_adder", "punishment": "ban"},
    "raidmode": {"enabled": False, "auto_joins": 10, "auto_seconds": 10, "join_action": "timeout"},
    "panic": {"enabled": False, "overwrites": {}},
    "automod": {"enabled": False, "whitelist": [], "spam_limit": 5, "spam_seconds": 5,
                "mention_limit": 5, "links": False, "invites": True, "badwords": []},
    "nightmode": {"enabled": False, "auto": False, "on": "23:00", "off": "06:00", "locked": []},
    "logs": {},
    "snapshot": {},
    "warns": {},
}
DATA = {}


def deep_fill(d, defaults):
    for k, v in defaults.items():
        if k not in d:
            d[k] = copy.deepcopy(v)
        elif isinstance(v, dict) and isinstance(d[k], dict):
            deep_fill(d[k], v)


def load():
    """Load persistent guild configuration; preserve a damaged file for recovery."""
    global DATA
    if not DATA_FILE.exists():
        DATA = {}
        return
    try:
        with DATA_FILE.open("r", encoding="utf-8") as f:
            parsed = json.load(f)
        DATA = parsed if isinstance(parsed, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        backup = DATA_FILE.with_name(f"{DATA_FILE.stem}.corrupt-{int(time.time())}.json")
        try:
            DATA_FILE.replace(backup)
            log.error("Config file was invalid; moved it to %s (%s)", backup.name, exc)
        except OSError:
            log.exception("Could not preserve invalid config file")
        DATA = {}


def save():
    """Atomic write prevents partial JSON if the process restarts mid-write."""
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="souvion-", suffix=".tmp", dir=str(DATA_FILE.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(DATA, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_name, DATA_FILE)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def gd(gid):
    k = str(gid)
    DATA.setdefault(k, {})
    deep_fill(DATA[k], DEFAULTS)
    return DATA[k]


# ───────────────────────── bot setup ─────────────────────────
async def get_prefix(bot_, msg):
    return gd(msg.guild.id)["prefix"] if msg.guild else "!"


intents = discord.Intents.default()
intents.guilds = True
intents.members = True
intents.moderation = True
intents.guild_messages = True
intents.message_content = True
intents.webhooks = True
bot = commands.Bot(command_prefix=get_prefix, intents=intents, help_command=None)

@bot.check
async def guild_context_guard(ctx):
    if ctx.guild is None and (ctx.command is None or ctx.command.qualified_name != "ping"):
        raise commands.NoPrivateMessage()
    return True

hits = defaultdict(deque)
join_times = defaultdict(deque)
spam_times = defaultdict(deque)


def emb(title, desc="", color=COLOR):
    return discord.Embed(title=title, description=desc, color=color)


def trusted(guild, uid, section):
    d = gd(guild.id)
    return (uid == guild.owner_id or uid in OWNER_IDS or uid == bot.user.id
            or uid in d[section]["whitelist"])


def admin():
    return commands.has_permissions(administrator=True)


async def send_log(guild, kind, title, desc, color=COLOR):
    cid = gd(guild.id)["logs"].get(kind)
    ch = guild.get_channel(cid) if cid else None
    if ch:
        try:
            e = emb(title, desc, color)
            e.timestamp = discord.utils.utcnow()
            await ch.send(embed=e)
        except discord.HTTPException:
            pass


# ───────────────────────── help panel ─────────────────────────
CATS = {
    "antinuke": ("🛡️", "Core Antinuke", [
        ("antinuke", "View Core Antinuke status", "Everyone"),
        ("antinuke enable", "Enable Core Antinuke", "Admin"),
        ("antinuke disable", "Disable Core Antinuke", "Admin"),
        ("antinuke status", "View Core/Super/Raid/Recovery status", "Everyone"),
        ("antinuke settings", "View all security thresholds", "Admin"),
        ("antinuke whitelist add @user", "Whitelist a user", "Admin"),
        ("antinuke whitelist remove @user", "Remove a user from whitelist", "Admin"),
        ("antinuke whitelist show", "Show Core Antinuke whitelist", "Admin"),
        ("antinuke whitelist reset", "Clear the whitelist", "Admin"),
        ("setthreshold <action> <limit> <period>", "Set a security action threshold", "Admin")]),
    "superantinuke": ("⚡", "SuperAntinuke", [
        ("superantinuke", "View SuperAntinuke status", "Everyone"),
        ("superantinuke enable", "Enable SuperAntinuke MAX", "Admin"),
        ("superantinuke disable", "Disable SuperAntinuke MAX", "Admin"),
        ("superantinuke config", "View burst/bot-add/punishment settings", "Admin"),
        ("superantinuke verify", "Check required bot permissions", "Everyone"),
        ("superantinuke whitelist add @user", "Whitelist a user", "Admin"),
        ("superantinuke whitelist remove @user", "Remove a user from whitelist", "Admin"),
        ("superantinuke whitelist show", "Show whitelist", "Admin"),
        ("superantinuke whitelist reset", "Clear the whitelist", "Admin")]),
    "raidmode": ("🚨", "Raidmode", [
        ("raidmode", "View Raidmode status", "Everyone"),
        ("raidmode on", "Enable Raidmode", "Admin"),
        ("raidmode off", "Disable Raidmode", "Admin"),
        ("raidmode status", "View Raidmode status", "Everyone")]),
    "automod": ("🤖", "AutoMod", [
        ("automod", "View AutoMod status", "Everyone"),
        ("automod on", "Enable AutoMod", "Admin"),
        ("automod off", "Disable AutoMod", "Admin"),
        ("automod config", "View AutoMod configuration", "Admin"),
        ("automod set <key> <value>", "Change an AutoMod setting live", "Admin"),
        ("automod whitelist add @user", "Whitelist a user", "Admin"),
        ("automod whitelist remove @user", "Remove a user from whitelist", "Admin")]),
    "nightmode": ("🌙", "Nightmode", [
        ("nightmode", "View Nightmode status and schedule", "Everyone"),
        ("nightmode enable", "Enable Nightmode", "Admin"),
        ("nightmode disable", "Disable Nightmode", "Admin"),
        ("nightmode status", "View Nightmode status", "Everyone"),
        ("nightmode schedule <on> <off>", "Set automatic schedule (HH:MM)", "Admin"),
        ("nightmode auto on/off", "Toggle automatic Nightmode", "Admin")]),
    "logging": ("📋", "Logging & Channels", [
        ("autologs", "View AutoLogs help", "Everyone"),
        ("autologs setup", "Create/reuse private security log channels", "Admin"),
        ("setlog <event> #channel", "Route an event to a log channel (security/mod/message/member)", "Admin")]),
    "recovery": ("🔄", "Recovery", [
        ("snapshot", "Save the current server structure", "Admin"),
        ("recovery", "Restore missing saved objects", "Admin")]),
    "tickets": ("🎫", "Tickets", [
        ("ticket", "View ticket help", "Everyone"),
        ("ticket setup", "Post the support ticket panel", "Manage Channels"),
        ("ticket create", "Create a private support ticket", "Everyone"),
        ("ticket close", "Close the current ticket", "Owner/Staff")]),
    "moderation": ("🔨", "Moderation", [
        ("mod", "View moderation help", "Everyone"),
        ("mod warn @user [reason]", "Warn a member", "Moderate Members"),
        ("mod timeout @user <minutes> [reason]", "Timeout a member", "Moderate Members"),
        ("mod kick @user [reason]", "Kick a member", "Kick Members"),
        ("mod ban @user [reason]", "Ban a member", "Ban Members")]),
    "tools": ("🖥️", "Server Tools", [
        ("help", "Open this interactive help panel", "Everyone"),
        ("ping", "Check bot latency", "Everyone"),
        ("prefix", "Show the current server prefix", "Manage Server"),
        ("prefix <new>", "Change the server prefix", "Manage Server"),
        ("autosetup", "Enable MAX security and private logs", "Admin"),
        ("securitysetup", "Open the interactive security setup panel", "Admin"),
        ("setupsecurity", "Alias for securitysetup", "Admin")]),
 
    "channelcontrol": ("🔒", "Channel Control", [
        ("lock", "Lock the current text channel", "Manage Channels"),
        ("unlock", "Unlock the current text channel", "Manage Channels"),
        ("lock #channel", "Lock a specified text channel", "Manage Channels"),
        ("unlock #channel", "Unlock a specified text channel", "Manage Channels")
    ]),

          
}


def main_help_embed(prefix):
    lines = "\n".join(f"{v[0]} {v[1]}" for v in CATS.values())
    e = emb("🛡️ Souvion Security • Help Panel",
            "**Advanced Protection • Server Control**\n\nSelect a category below to view every public command.")
    e.add_field(name="🚀 Security / Server Modules", value=lines, inline=False)
    e.add_field(name="⚙️ Quick Setup",
                value=f"`{prefix}securitysetup` • Interactive setup panel\n`{prefix}autosetup` • One-command MAX security setup",
                inline=False)
    e.set_footer(text=f"Prefix: {prefix} • Select a category below")
    return e


def cat_embed(key, prefix, user):
    icon, name, rows = CATS[key]
    desc = "\n".join(f"`{prefix}{c}` — {d} • **{p}**" for c, d, p in rows)
    e = emb(f"{icon} {name} Commands", desc)
    e.set_footer(text=f"Prefix: {prefix} • Requested by {user}")
    return e


class HelpView(discord.ui.View):
    def __init__(self, author_id, prefix):
        super().__init__(timeout=300)
        self.author_id, self.prefix = author_id, prefix
        sel = discord.ui.Select(
            placeholder="🚀 Select a Security / Server Module",
            options=[discord.SelectOption(label=v[1], value=k, emoji=v[0]) for k, v in CATS.items()])
        sel.callback = self.on_select
        self.add_item(sel)

    async def interaction_check(self, i):
        if i.user.id != self.author_id:
            await i.response.send_message("This panel isn't yours. Run the help command yourself.", ephemeral=True)
            return False
        return True

    async def on_select(self, i: discord.Interaction):
        await i.response.edit_message(embed=cat_embed(i.data["values"][0], self.prefix, i.user))

    @discord.ui.button(label="Back", emoji="⬅️", style=discord.ButtonStyle.secondary)
    async def back(self, i: discord.Interaction, b):
        await i.response.edit_message(embed=main_help_embed(self.prefix))


@bot.command(name="help")
async def help_cmd(ctx):
    p = gd(ctx.guild.id)["prefix"]
    await ctx.send(embed=main_help_embed(p), view=HelpView(ctx.author.id, p))


@bot.command()
async def ping(ctx):
    await ctx.send(embed=emb("🏓 Pong", f"Latency: **{round(bot.latency * 1000)}ms**"))


@bot.command()
@commands.has_permissions(manage_guild=True)
async def prefix(ctx, new: str = None):
    d = gd(ctx.guild.id)
    if not new:
        return await ctx.send(embed=emb("📌 Server Prefix", f"`{d['prefix']}`"))
    if len(new) > 3:
        return await ctx.send("Prefix max 3 characters.")
    d["prefix"] = new
    save()
    await ctx.send(embed=emb("📌 Prefix Updated", f"New prefix: `{new}`"))


# ───────────────────────── punish / recovery ─────────────────────────
async def punish(guild, user, reason, mode="ban"):
    # Fail closed on self/owner and never attempt an action the bot cannot perform.
    if user.id == guild.owner_id or (bot.user and user.id == bot.user.id):
        log.warning("Blocked punishment attempt against owner/bot in guild %s", guild.id)
        return
    member = guild.get_member(user.id)
    try:
        if mode == "ban":
            await guild.ban(user, reason=reason)
        elif mode == "kick" and member and guild.me and member.top_role < guild.me.top_role:
            await guild.kick(member, reason=reason)
        elif mode in ("strip", "remove_roles") and member and guild.me:
            roles = [r for r in member.roles if r != guild.default_role and r < guild.me.top_role and not r.managed]
            if roles:
                await member.remove_roles(*roles, reason=reason)
        else:
            log.warning("Punishment skipped (mode=%s, member=%s) in guild %s", mode, bool(member), guild.id)
    except (discord.Forbidden, discord.HTTPException):
        log.exception("Punishment failed in guild %s", guild.id)
    await send_log(guild, "security", "🚨 Antinuke Triggered",
                   f"User: {user.mention} (`{user.id}`)\nReason: {reason}\nAction: **{mode}**", 0xED4245)


def serialize_overwrites(channel):
    records = []
    for target, overwrite in channel.overwrites.items():
        if isinstance(target, discord.Role):
            target_type = "role"
        elif isinstance(target, discord.Member):
            target_type = "member"
        else:
            continue
        allow, deny = overwrite.pair()
        records.append({"type": target_type, "id": target.id, "name": target.name,
                        "allow": allow.value, "deny": deny.value})
    return records


def restore_overwrites(guild, records):
    result = {}
    for record in records or []:
        target = None
        if record.get("type") == "role":
            target_id = int(record.get("id", 0))
            target = guild.get_role(target_id)
            if target is None and (record.get("name") == "@everyone" or target_id == guild.id):
                target = guild.default_role
            if target is None:
                target = discord.utils.get(guild.roles, name=record.get("name", ""))
        elif record.get("type") == "member":
            target = guild.get_member(int(record.get("id", 0)))
        if target is not None:
            allow = discord.Permissions(int(record.get("allow", 0)))
            deny = discord.Permissions(int(record.get("deny", 0)))
            result[target] = discord.PermissionOverwrite.from_pair(allow, deny)
    return result


async def take_snapshot(guild):
    snap = {
        "created_at": int(time.time()),
        "roles": [{"id": r.id, "name": r.name, "color": r.color.value, "perms": r.permissions.value,
                   "hoist": r.hoist, "mention": r.mentionable, "position": r.position}
                  for r in guild.roles if not r.managed and r != guild.default_role],
        "channels": [{"id": c.id, "name": c.name, "type": c.type.name,
                      "category": c.category.name if getattr(c, "category", None) else None,
                      "topic": getattr(c, "topic", None), "nsfw": getattr(c, "nsfw", False),
                      "slow": getattr(c, "slowmode_delay", 0), "position": c.position,
                      "overwrites": serialize_overwrites(c)}
                     for c in guild.channels
                     if c.type.name in ("text", "voice", "category")],
    }
    gd(guild.id)["snapshot"] = snap
    save()
    return len(snap["roles"]), len(snap["channels"])


async def restore(guild, restore_permissions=False):
    """Restore missing objects; only overwrite existing permissions on explicit admin recovery."""
    snap = gd(guild.id).get("snapshot")
    if not snap:
        return None
    made = 0
    for r in snap.get("roles", []):
        if discord.utils.get(guild.roles, name=r["name"]) is None:
            try:
                await guild.create_role(name=r["name"], colour=discord.Colour(r["color"]),
                                        permissions=discord.Permissions(r["perms"]),
                                        hoist=r["hoist"], mentionable=r["mention"],
                                        reason="Souvion snapshot recovery")
                made += 1
            except (discord.Forbidden, discord.HTTPException):
                log.exception("Could not restore role %s", r.get("name"))

    cats = {c.name: c for c in guild.categories}
    for c in [x for x in snap.get("channels", []) if x["type"] == "category"]:
        ow = restore_overwrites(guild, c.get("overwrites", []))
        current = cats.get(c["name"])
        try:
            if current is None:
                current = await guild.create_category(c["name"], overwrites=ow,
                                                      reason="Souvion snapshot recovery")
                cats[c["name"]] = current
                made += 1
            elif restore_permissions:
                await current.edit(overwrites=ow, reason="Souvion snapshot permission recovery")
        except (discord.Forbidden, discord.HTTPException):
            log.exception("Could not restore category %s", c.get("name"))

    for c in [x for x in snap.get("channels", []) if x["type"] != "category"]:
        cat = cats.get(c.get("category"))
        ow = restore_overwrites(guild, c.get("overwrites", []))
        current = discord.utils.get(guild.channels, name=c["name"], type=getattr(discord.ChannelType, c["type"], None))
        try:
            if current is None:
                if c["type"] == "text":
                    await guild.create_text_channel(c["name"], category=cat, topic=c.get("topic"),
                                                    nsfw=c.get("nsfw", False), slowmode_delay=c.get("slow", 0),
                                                    overwrites=ow, reason="Souvion snapshot recovery")
                elif c["type"] == "voice":
                    await guild.create_voice_channel(c["name"], category=cat, overwrites=ow,
                                                     reason="Souvion snapshot recovery")
                made += 1
            elif restore_permissions:
                edits = {"overwrites": ow}
                if isinstance(current, discord.TextChannel):
                    edits.update(topic=c.get("topic"), nsfw=c.get("nsfw", False),
                                 slowmode_delay=c.get("slow", 0))
                if cat is not None:
                    edits["category"] = cat
                await current.edit(reason="Souvion snapshot permission recovery", **edits)
        except (discord.Forbidden, discord.HTTPException):
            log.exception("Could not restore channel %s", c.get("name"))
    return made


@bot.command()
@admin()
async def snapshot(ctx):
    r, c = await take_snapshot(ctx.guild)
    await ctx.send(embed=emb("📸 Snapshot Saved", f"Roles: **{r}** • Channels/Categories: **{c}**"))


@bot.command()
@admin()
async def recovery(ctx):
    made = await restore(ctx.guild, restore_permissions=True)
    if made is None:
        return await ctx.send(f"No snapshot. Run `{gd(ctx.guild.id)['prefix']}snapshot` first.")
    await ctx.send(embed=emb("🔄 Recovery Complete", f"Restored **{made}** missing objects."))


# ───────────────────────── antinuke engine ─────────────────────────
async def audit_actor(guild, action, target_id=None):
    try:
        async for e in guild.audit_logs(limit=6, action=action):
            if (discord.utils.utcnow() - e.created_at).total_seconds() > 15:
                continue
            if target_id is None or (e.target and getattr(e.target, "id", None) == target_id):
                return e.user
    except (discord.Forbidden, discord.HTTPException):
        pass
    return None


async def track(guild, user, key):
    if user is None:
        return False
    d = gd(guild.id)
    now = time.time()
    reasons, mode = [], "ban"
    an, sa = d["antinuke"], d["superantinuke"]
    if an["enabled"] and not trusted(guild, user.id, "antinuke"):
        lim, per = an["thresholds"][key]
        dq = hits[(guild.id, user.id, key)]
        dq.append(now)
        prune_window(dq, now, per)
        if len(dq) >= lim:
            reasons.append(f"Core Antinuke: {key} x{len(dq)}")
            mode = an["punishment"]
    if sa["enabled"] and not trusted(guild, user.id, "superantinuke"):
        lim, per = sa["burst"]
        dq = hits[(guild.id, user.id, "burst")]
        dq.append(now)
        prune_window(dq, now, per)
        if len(dq) >= lim:
            reasons.append(f"SuperAntinuke burst: {len(dq)} actions/{per}s")
            mode = sa["punishment"]
    if reasons:
        for k in list(hits):
            if k[0] == guild.id and k[1] == user.id:
                hits[k].clear()
        await punish(guild, user, " | ".join(reasons), mode)
        await restore(guild)
        return True
    return False


@bot.event
async def on_guild_channel_delete(ch):
    a = await audit_actor(ch.guild, discord.AuditLogAction.channel_delete, ch.id)
    await track(ch.guild, a, "channel_delete")


@bot.event
async def on_guild_channel_create(ch):
    a = await audit_actor(ch.guild, discord.AuditLogAction.channel_create, ch.id)
    if await track(ch.guild, a, "channel_create"):
        try:
            await ch.delete(reason="Antinuke: created by nuker")
        except discord.HTTPException:
            pass


@bot.event
async def on_guild_role_delete(role):
    a = await audit_actor(role.guild, discord.AuditLogAction.role_delete, role.id)
    await track(role.guild, a, "role_delete")


@bot.event
async def on_guild_role_create(role):
    a = await audit_actor(role.guild, discord.AuditLogAction.role_create, role.id)
    if await track(role.guild, a, "role_create"):
        try:
            await role.delete(reason="Antinuke: created by nuker")
        except discord.HTTPException:
            pass


@bot.event
async def on_guild_role_update(before, after):
    dangerous = discord.Permissions(administrator=True, manage_guild=True, manage_roles=True,
                                    manage_channels=True, ban_members=True, kick_members=True,
                                    manage_webhooks=True, manage_messages=True, mention_everyone=True)
    if not dangerous_permission_escalation(before.permissions.value, after.permissions.value, dangerous.value):
        return
    actor = await audit_actor(after.guild, discord.AuditLogAction.role_update, after.id)
    if await track(after.guild, actor, "role_update"):
        try:
            await after.edit(permissions=before.permissions, reason="Antinuke: reverted dangerous role permission change")
        except (discord.Forbidden, discord.HTTPException):
            log.exception("Could not revert role permissions for role %s", after.id)


@bot.event
async def on_guild_channel_update(before, after):
    if before.overwrites != after.overwrites:
        guild = after.guild
        actor = None
        # Permission overwrite audit entries point at the affected channel in extra.channel.
        for action in (discord.AuditLogAction.overwrite_create, discord.AuditLogAction.overwrite_update,
                       discord.AuditLogAction.overwrite_delete):
            try:
                async for entry in guild.audit_logs(limit=5, action=action):
                    age = (discord.utils.utcnow() - entry.created_at).total_seconds()
                    extra_channel = getattr(getattr(entry, "extra", None), "channel", None)
                    if 0 <= age <= 12 and extra_channel and extra_channel.id == after.id:
                        actor = entry.user
                        break
            except (discord.Forbidden, discord.HTTPException):
                continue
            if actor:
                break
        if await track(guild, actor, "channel_update"):
            try:
                await after.edit(overwrites=before.overwrites, reason="Antinuke: reverted suspicious permission overwrite change")
            except (discord.Forbidden, discord.HTTPException):
                log.exception("Could not revert channel overwrites for channel %s", after.id)


@bot.event
async def on_member_ban(guild, user):
    a = await audit_actor(guild, discord.AuditLogAction.ban, user.id)
    await track(guild, a, "ban")
    await send_log(guild, "mod", "🔨 Member Banned", f"{user} (`{user.id}`) by {a.mention if a else 'unknown'}", 0xED4245)


@bot.event
async def on_webhooks_update(channel):
    # Discord emits one update event for either webhook creation or deletion.
    # Inspect both audit actions and use the newest matching entry to avoid counting
    # one event twice or relying only on webhook_create.
    guild = channel.guild
    candidates = []
    for action in (discord.AuditLogAction.webhook_create, discord.AuditLogAction.webhook_delete):
        try:
            async for entry in guild.audit_logs(limit=4, action=action):
                age = (discord.utils.utcnow() - entry.created_at).total_seconds()
                if 0 <= age <= 12 and entry.user:
                    candidates.append(entry)
                    break
        except (discord.Forbidden, discord.HTTPException):
            continue
    if candidates:
        entry = max(candidates, key=lambda e: e.created_at)
        await track(guild, entry.user, "webhook")


@bot.event
async def on_member_remove(member):
    g = member.guild
    a = await audit_actor(g, discord.AuditLogAction.kick, member.id)
    if a:
        await track(g, a, "kick")
    await send_log(g, "member", "📤 Member Left", f"{member} (`{member.id}`)", 0xFEE75C)


@bot.event
async def on_member_join(member):
    g = member.guild
    d = gd(g.id)
    # SuperAntinuke: unauthorized bot add
    if member.bot and d["superantinuke"]["enabled"]:
        adder = await audit_actor(g, discord.AuditLogAction.bot_add, member.id)
        if adder and not trusted(g, adder.id, "superantinuke"):
            try:
                await g.kick(member, reason="SuperAntinuke: unauthorized bot")
            except discord.HTTPException:
                pass
            await punish(g, adder, "Added a bot without whitelist", d["superantinuke"]["punishment"])
            return
    # Raidmode
    rm = d["raidmode"]
    now = time.time()
    dq = join_times[g.id]
    dq.append(now)
    prune_window(dq, now, rm["auto_seconds"])
    if should_auto_enable_raidmode(rm["enabled"], len(dq), rm["auto_joins"]):
        rm["enabled"] = True
        save()
        await send_log(g, "security", "🚨 Raidmode Auto-Enabled",
                       f"{len(dq)} joins in {rm['auto_seconds']}s", 0xED4245)
    if rm["enabled"] and not member.bot:
        # Safer default than mass-kicking: temporarily timeout new arrivals. This
        # requires Moderate Members and can be changed by an administrator later.
        try:
            await member.timeout(dt.timedelta(minutes=10), reason="Raidmode active; temporary anti-raid restriction")
            await send_log(g, "security", "🚨 Raidmode action", f"Temporarily timed out {member} (`{member.id}`) during raid mode.", 0xED4245)
        except (discord.Forbidden, discord.HTTPException):
            log.warning("Could not apply raid timeout for member %s in guild %s", member.id, g.id)
        return
    await send_log(g, "member", "📥 Member Joined", f"{member.mention} (`{member.id}`)", 0x57F287)


# ───────────────────────── automod ─────────────────────────
INVITE_RE = re.compile(r"(discord\.gg|discord(?:app)?\.com/invite)/\w+", re.I)
LINK_RE = re.compile(r"https?://\S+", re.I)


async def automod_check(m: discord.Message):
    d = gd(m.guild.id)
    am = d["automod"]
    if not am["enabled"] or m.author.guild_permissions.administrator or m.author.id in am["whitelist"]:
        return
    reason = None
    txt = m.content.lower()
    if am["invites"] and INVITE_RE.search(m.content):
        reason = "Invite link"
    elif am["links"] and LINK_RE.search(m.content):
        reason = "Link"
    elif len(m.mentions) + len(m.role_mentions) >= am["mention_limit"]:
        reason = "Mass mention"
    elif any(w and w in txt for w in am["badwords"]):
        reason = "Blocked word"
    else:
        dq = spam_times[(m.guild.id, m.author.id)]
        now = time.time()
        dq.append(now)
        prune_window(dq, now, am["spam_seconds"])
        if len(dq) >= am["spam_limit"]:
            reason = "Spam"
            dq.clear()
            try:
                await m.author.timeout(dt.timedelta(minutes=5), reason="AutoMod spam")
            except discord.HTTPException:
                pass
    if reason:
        try:
            await m.delete()
            await m.channel.send(f"{m.author.mention} ⚠️ AutoMod: **{reason}** not allowed.", delete_after=5)
        except discord.HTTPException:
            pass
        await send_log(m.guild, "mod", "🤖 AutoMod", f"{m.author.mention} — **{reason}** in {m.channel.mention}", 0xFEE75C)


@bot.event
async def on_message(m):
    if m.author.bot or not m.guild:
        return
    await automod_check(m)
    await bot.process_commands(m)


@bot.event
async def on_message_delete(m):
    if m.guild and not m.author.bot:
        await send_log(m.guild, "message", "🗑️ Message Deleted",
                       f"{m.author.mention} in {m.channel.mention}\n{(m.content or '*no text*')[:900]}", 0xED4245)


@bot.event
async def on_message_edit(a, b):
    if a.guild and not a.author.bot and a.content != b.content:
        await send_log(a.guild, "message", "✏️ Message Edited",
                       f"{a.author.mention} in {a.channel.mention}\n**Before:** {a.content[:450]}\n**After:** {b.content[:450]}")


# ───────────────────────── whitelist helper ─────────────────────────
def add_whitelist(parent, section):
    @parent.group(name="whitelist", invoke_without_command=True)
    @admin()
    async def wl(ctx):
        await ctx.send("Use: `add @user` / `remove @user` / `show` / `reset`")

    @wl.command(name="add")
    @admin()
    async def wl_add(ctx, user: discord.User):
        w = gd(ctx.guild.id)[section]["whitelist"]
        if user.id not in w:
            w.append(user.id)
            save()
        await ctx.send(embed=emb("✅ Whitelisted", f"{user.mention} added."))

    @wl.command(name="remove")
    @admin()
    async def wl_remove(ctx, user: discord.User):
        w = gd(ctx.guild.id)[section]["whitelist"]
        if user.id in w:
            w.remove(user.id)
            save()
        await ctx.send(embed=emb("✅ Removed", f"{user.mention} removed."))

    @wl.command(name="show")
    @admin()
    async def wl_show(ctx):
        w = gd(ctx.guild.id)[section]["whitelist"]
        await ctx.send(embed=emb("📃 Whitelist", "\n".join(f"<@{i}>" for i in w) or "Empty"))

    @wl.command(name="reset")
    @admin()
    async def wl_reset(ctx):
        gd(ctx.guild.id)[section]["whitelist"] = []
        save()
        await ctx.send(embed=emb("♻️ Whitelist Cleared"))


def onoff(v):
    return "🟢 ON" if v else "🔴 OFF"


# ───────────────────────── core antinuke ─────────────────────────
def status_embed(guild):
    d = gd(guild.id)
    e = emb("🛡️ Security Status")
    e.add_field(name="Core Antinuke", value=onoff(d["antinuke"]["enabled"]))
    e.add_field(name="SuperAntinuke", value=onoff(d["superantinuke"]["enabled"]))
    e.add_field(name="Raidmode", value=onoff(d["raidmode"]["enabled"]))
    e.add_field(name="AutoMod", value=onoff(d["automod"]["enabled"]))
    e.add_field(name="Nightmode", value=onoff(d["nightmode"]["enabled"]))
    e.add_field(name="Recovery", value="🟢 Snapshot saved" if d["snapshot"] else "🔴 No snapshot")
    return e


@bot.group(invoke_without_command=True)
async def antinuke(ctx):
    d = gd(ctx.guild.id)["antinuke"]
    await ctx.send(embed=emb("🛡️ Core Antinuke", f"Status: {onoff(d['enabled'])}\nPunishment: `{d['punishment']}`"))


@antinuke.command(name="enable")
@admin()
async def an_enable(ctx):
    gd(ctx.guild.id)["antinuke"]["enabled"] = True
    save()
    await ctx.send(embed=emb("🛡️ Core Antinuke", "🟢 Enabled", 0x57F287))


@antinuke.command(name="disable")
@admin()
async def an_disable(ctx):
    gd(ctx.guild.id)["antinuke"]["enabled"] = False
    save()
    await ctx.send(embed=emb("🛡️ Core Antinuke", "🔴 Disabled", 0xED4245))


@antinuke.command(name="status")
async def an_status(ctx):
    await ctx.send(embed=status_embed(ctx.guild))


@antinuke.command(name="settings")
@admin()
async def an_settings(ctx):
    t = gd(ctx.guild.id)["antinuke"]["thresholds"]
    await ctx.send(embed=emb("⚙️ Thresholds", "\n".join(f"`{k}` — {v[0]} per {v[1]}s" for k, v in t.items())))


add_whitelist(antinuke, "antinuke")


@bot.command()
@admin()
async def setthreshold(ctx, action: str, limit: int, period: int):
    t = gd(ctx.guild.id)["antinuke"]["thresholds"]
    if action not in t:
        return await ctx.send("Actions: " + ", ".join(f"`{k}`" for k in t))
    if limit < 1 or period < 1:
        return await ctx.send("Limit and period must be 1 or more.")
    t[action] = [limit, period]
    save()
    await ctx.send(embed=emb("✅ Threshold Set", f"`{action}` → **{limit}** per **{period}s**"))


# ───────────────────────── superantinuke ─────────────────────────
@bot.group(invoke_without_command=True)
async def superantinuke(ctx):
    d = gd(ctx.guild.id)["superantinuke"]
    await ctx.send(embed=emb("⚡ SuperAntinuke", f"Status: {onoff(d['enabled'])}"))


@superantinuke.command(name="enable")
@admin()
async def sa_enable(ctx):
    gd(ctx.guild.id)["superantinuke"]["enabled"] = True
    save()
    await ctx.send(embed=emb("⚡ SuperAntinuke MAX", "🟢 Enabled", 0x57F287))


@superantinuke.command(name="disable")
@admin()
async def sa_disable(ctx):
    gd(ctx.guild.id)["superantinuke"]["enabled"] = False
    save()
    await ctx.send(embed=emb("⚡ SuperAntinuke MAX", "🔴 Disabled", 0xED4245))


@superantinuke.command(name="config")
@admin()
async def sa_config(ctx):
    d = gd(ctx.guild.id)["superantinuke"]
    await ctx.send(embed=emb("⚡ SuperAntinuke Config",
                             f"Burst: **{d['burst'][0]}** actions / **{d['burst'][1]}s**\n"
                             f"Bot-add: `{d['bot_add']}`\nPunishment: `{d['punishment']}`"))


@superantinuke.command(name="verify")
async def sa_verify(ctx):
    p = ctx.guild.me.guild_permissions
    need = ["ban_members", "kick_members", "manage_channels", "manage_roles",
            "view_audit_log", "manage_guild", "moderate_members", "manage_messages"]
    await ctx.send(embed=emb("🔍 Permission Check",
                             "\n".join(f"{'✅' if getattr(p, n) else '❌'} {n}" for n in need)))


add_whitelist(superantinuke, "superantinuke")


# ───────────────────────── raidmode ─────────────────────────
@bot.group(invoke_without_command=True)
async def raidmode(ctx):
    await ctx.send(embed=emb("🚨 Raidmode", onoff(gd(ctx.guild.id)["raidmode"]["enabled"])))


@raidmode.command(name="on")
@admin()
async def rm_on(ctx):
    gd(ctx.guild.id)["raidmode"]["enabled"] = True
    save()
    await ctx.send(embed=emb("🚨 Raidmode", "🟢 Enabled — new human joins will receive a temporary 10-minute timeout when the bot has permission.", 0xED4245))


@raidmode.command(name="off")
@admin()
async def rm_off(ctx):
    gd(ctx.guild.id)["raidmode"]["enabled"] = False
    save()
    await ctx.send(embed=emb("🚨 Raidmode", "🔴 Disabled", 0x57F287))


@raidmode.command(name="status")
async def rm_status(ctx):
    await ctx.send(embed=emb("🚨 Raidmode", onoff(gd(ctx.guild.id)["raidmode"]["enabled"])))


# ───────────────────────── automod commands ─────────────────────────
@bot.group(invoke_without_command=True)
async def automod(ctx):
    await ctx.send(embed=emb("🤖 AutoMod", onoff(gd(ctx.guild.id)["automod"]["enabled"])))


@automod.command(name="on")
@admin()
async def am_on(ctx):
    gd(ctx.guild.id)["automod"]["enabled"] = True
    save()
    await ctx.send(embed=emb("🤖 AutoMod", "🟢 Enabled", 0x57F287))


@automod.command(name="off")
@admin()
async def am_off(ctx):
    gd(ctx.guild.id)["automod"]["enabled"] = False
    save()
    await ctx.send(embed=emb("🤖 AutoMod", "🔴 Disabled", 0xED4245))


@automod.command(name="config")
@admin()
async def am_config(ctx):
    a = gd(ctx.guild.id)["automod"]
    keys = ["spam_limit", "spam_seconds", "mention_limit", "links", "invites", "badwords"]
    await ctx.send(embed=emb("🤖 AutoMod Config", "\n".join(f"`{k}` = {a[k]}" for k in keys)))


@automod.command(name="set")
@admin()
async def am_set(ctx, key: str, *, value: str):
    a = gd(ctx.guild.id)["automod"]
    if key in ("spam_limit", "spam_seconds", "mention_limit"):
        if not value.isdigit():
            return await ctx.send("Value must be a number.")
        a[key] = int(value)
    elif key in ("links", "invites"):
        a[key] = value.lower() in ("on", "true", "yes", "1")
    elif key == "badwords":
        a[key] = [w.strip().lower() for w in value.split(",") if w.strip()]
    else:
        return await ctx.send("Keys: spam_limit, spam_seconds, mention_limit, links, invites, badwords")
    save()
    await ctx.send(embed=emb("✅ AutoMod Updated", f"`{key}` = {a[key]}"))


add_whitelist(automod, "automod")


# ───────────────────────── nightmode ─────────────────────────
async def night_apply(guild, enable):
    n = gd(guild.id)["nightmode"]
    ev = guild.default_role
    if enable:
        # Store the previous tri-state permission instead of blindly clearing it later.
        locked = n.get("locked", {})
        if not isinstance(locked, dict):  # migrate legacy list format
            locked = {str(cid): None for cid in locked}
        for ch in guild.text_channels:
            if (ch.topic or "").startswith("ticket:"):
                continue
            ow = ch.overwrites_for(ev)
            if ow.send_messages is not False:
                locked.setdefault(str(ch.id), ow.send_messages)
                ow.send_messages = False
                try:
                    await ch.set_permissions(ev, overwrite=ow, reason="Nightmode ON")
                except (discord.Forbidden, discord.HTTPException):
                    log.exception("Could not lock channel %s for Nightmode", ch.id)
                await asyncio.sleep(0.15)
        n["locked"] = locked
    else:
        locked = n.get("locked", {})
        if isinstance(locked, dict):
            entries = locked.items()
        else:  # legacy format: old versions did not save prior values
            entries = ((str(cid), None) for cid in locked)
        for raw_id, previous_value in list(entries):
            ch = guild.get_channel(int(raw_id))
            if ch:
                ow = ch.overwrites_for(ev)
                ow.send_messages = previous_value
                try:
                    await ch.set_permissions(ev, overwrite=ow, reason="Nightmode OFF")
                except (discord.Forbidden, discord.HTTPException):
                    log.exception("Could not unlock channel %s for Nightmode", ch.id)
                await asyncio.sleep(0.15)
        n["locked"] = {}
    n["enabled"] = enable
    save()
    await send_log(guild, "security", "🌙 Nightmode", "Enabled" if enable else "Disabled")


def night_embed(guild):
    n = gd(guild.id)["nightmode"]
    return emb("🌙 Nightmode",
               f"Status: {onoff(n['enabled'])}\nAuto: {onoff(n['auto'])}\n"
               f"Schedule (IST): ON **{n['on']}** → OFF **{n['off']}**")


@bot.group(invoke_without_command=True)
async def nightmode(ctx):
    await ctx.send(embed=night_embed(ctx.guild))


@nightmode.command(name="status")
async def nm_status(ctx):
    await ctx.send(embed=night_embed(ctx.guild))


@nightmode.command(name="enable")
@admin()
async def nm_enable(ctx):
    async with ctx.typing():
        await night_apply(ctx.guild, True)
    await ctx.send(embed=emb("🌙 Nightmode", "🟢 Enabled — chat locked for @everyone"))


@nightmode.command(name="disable")
@admin()
async def nm_disable(ctx):
    async with ctx.typing():
        await night_apply(ctx.guild, False)
    await ctx.send(embed=emb("🌙 Nightmode", "🔴 Disabled — chat unlocked"))


@nightmode.command(name="schedule")
@admin()
async def nm_schedule(ctx, on: str, off: str):
    try:
        for t in (on, off):
            dt.datetime.strptime(t, "%H:%M")
    except ValueError:
        return await ctx.send("Use 24h format HH:MM, e.g. `23:00 06:00`")
    n = gd(ctx.guild.id)["nightmode"]
    n["on"], n["off"] = on, off
    save()
    await ctx.send(embed=night_embed(ctx.guild))


@nightmode.command(name="auto")
@admin()
async def nm_auto(ctx, mode: str):
    gd(ctx.guild.id)["nightmode"]["auto"] = mode.lower() in ("on", "true", "yes")
    save()
    await ctx.send(embed=night_embed(ctx.guild))


@tasks.loop(seconds=30)
async def night_loop():
    now = dt.datetime.now(TZ).strftime("%H:%M")
    for g in bot.guilds:
        n = gd(g.id)["nightmode"]
        if not n["auto"]:
            continue
        if now == n["on"] and not n["enabled"]:
            await night_apply(g, True)
        elif now == n["off"] and n["enabled"]:
            await night_apply(g, False)


# ───────────────────────── logging ─────────────────────────
LOG_EVENTS = ["security", "mod", "message", "member"]


async def setup_logs(guild):
    d = gd(guild.id)
    ow = {guild.default_role: discord.PermissionOverwrite(view_channel=False),
          guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True)}
    cat = discord.utils.get(guild.categories, name="Souvion Logs")
    if cat is None:
        cat = await guild.create_category("Souvion Logs", overwrites=ow, reason="Souvion private log setup")
    else:
        await cat.edit(overwrites=ow, reason="Souvion private log setup")
    for ev in LOG_EVENTS:
        name = f"{ev}-logs"
        ch = discord.utils.get(cat.text_channels, name=name)
        if ch is None:
            ch = await guild.create_text_channel(name, category=cat, overwrites=ow,
                                                 reason="Souvion private log setup")
        else:
            await ch.edit(overwrites=ow, reason="Souvion private log setup")
        d["logs"][ev] = ch.id
    save()


@bot.group(invoke_without_command=True)
async def autologs(ctx):
    p = gd(ctx.guild.id)["prefix"]
    await ctx.send(embed=emb("📋 AutoLogs",
                             f"`{p}autologs setup` — create private log channels\n"
                             f"`{p}setlog <event> #channel` — events: {', '.join(LOG_EVENTS)}"))


@autologs.command(name="setup")
@admin()
async def autologs_setup(ctx):
    await setup_logs(ctx.guild)
    await ctx.send(embed=emb("📋 AutoLogs", "Private log channels ready ✅", 0x57F287))


@bot.command()
@admin()
async def setlog(ctx, event: str, channel: discord.TextChannel):
    if event not in LOG_EVENTS:
        return await ctx.send("Events: " + ", ".join(LOG_EVENTS))
    gd(ctx.guild.id)["logs"][event] = channel.id
    save()
    await ctx.send(embed=emb("✅ Log Routed", f"`{event}` → {channel.mention}"))


# ───────────────────────── tickets ─────────────────────────
async def open_ticket(guild, user, respond):
    for c in guild.text_channels:
        if c.topic == f"ticket:{user.id}":
            return await respond(f"You already have a ticket: {c.mention}")
    cat = discord.utils.get(guild.categories, name="Tickets") or await guild.create_category("Tickets")
    ow = {guild.default_role: discord.PermissionOverwrite(view_channel=False),
          user: discord.PermissionOverwrite(view_channel=True, send_messages=True, attach_files=True),
          guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, manage_channels=True)}
    for r in guild.roles:
        if r.permissions.manage_channels or r.permissions.administrator:
            if not r.is_default() and not r.managed:
                ow[r] = discord.PermissionOverwrite(view_channel=True, send_messages=True)
    ch = await guild.create_text_channel(f"ticket-{user.name}"[:90], category=cat,
                                         overwrites=ow, topic=f"ticket:{user.id}")
    await ch.send(f"{user.mention}", embed=emb("🎫 Support Ticket",
                  "Staff will be with you shortly. Use the ticket close command to close this ticket."))
    await respond(f"Ticket created: {ch.mention}")


class TicketPanel(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Create Ticket", emoji="🎫", style=discord.ButtonStyle.primary,
                       custom_id="souvion:ticket:create")
    async def create(self, i: discord.Interaction, b):
        await i.response.defer(ephemeral=True)
        await open_ticket(i.guild, i.user, lambda t: i.followup.send(t, ephemeral=True))


@bot.group(invoke_without_command=True)
async def ticket(ctx):
    p = gd(ctx.guild.id)["prefix"]
    await ctx.send(embed=emb("🎫 Tickets", f"`{p}ticket setup` • `{p}ticket create` • `{p}ticket close`"))


@ticket.command(name="setup")
@commands.has_permissions(manage_channels=True)
async def ticket_setup(ctx):
    await ctx.send(embed=emb("🎫 Support", "Need help? Click the button below to open a private ticket."),
                   view=TicketPanel())


@ticket.command(name="create")
async def ticket_create(ctx):
    await open_ticket(ctx.guild, ctx.author, ctx.send)


@ticket.command(name="close")
async def ticket_close(ctx):
    t = ctx.channel.topic or ""
    if not t.startswith("ticket:"):
        return await ctx.send("This isn't a ticket channel.")
    if not (ctx.author.guild_permissions.manage_channels or str(ctx.author.id) == t.split(":")[1]):
        return await ctx.send("Only the ticket owner or staff can close this.")
    await ctx.send("🔒 Closing ticket in 5 seconds...")
    await asyncio.sleep(5)
    await ctx.channel.delete(reason=f"Ticket closed by {ctx.author}")


# ───────────────────────── moderation ─────────────────────────
def can_act(ctx, m: discord.Member):
    return (m != ctx.author and m.id != ctx.guild.owner_id and
            (ctx.author.id == ctx.guild.owner_id or ctx.author.top_role > m.top_role) and
            ctx.guild.me.top_role > m.top_role)


@bot.group(invoke_without_command=True)
async def mod(ctx):
    p = gd(ctx.guild.id)["prefix"]
    await ctx.send(embed=cat_embed("moderation", p, ctx.author))


@mod.command(name="warn")
@commands.has_permissions(moderate_members=True)
async def mod_warn(ctx, member: discord.Member, *, reason: str = "No reason"):
    w = gd(ctx.guild.id)["warns"].setdefault(str(member.id), [])
    w.append({"by": ctx.author.id, "reason": reason, "t": int(time.time())})
    save()
    await ctx.send(embed=emb("⚠️ Warned", f"{member.mention} — {reason}\nTotal warns: **{len(w)}**", 0xFEE75C))
    await send_log(ctx.guild, "mod", "⚠️ Warn", f"{member.mention} by {ctx.author.mention}: {reason}")


@mod.command(name="timeout")
@commands.has_permissions(moderate_members=True)
async def mod_timeout(ctx, member: discord.Member, minutes: int, *, reason: str = "No reason"):
    if not can_act(ctx, member):
        return await ctx.send("❌ Can't act on that member (role hierarchy).")
    await member.timeout(dt.timedelta(minutes=minutes), reason=reason)
    await ctx.send(embed=emb("⏳ Timed Out", f"{member.mention} for **{minutes}m** — {reason}", 0xFEE75C))
    await send_log(ctx.guild, "mod", "⏳ Timeout", f"{member.mention} {minutes}m by {ctx.author.mention}: {reason}")


@mod.command(name="kick")
@commands.has_permissions(kick_members=True)
async def mod_kick(ctx, member: discord.Member, *, reason: str = "No reason"):
    if not can_act(ctx, member):
        return await ctx.send("❌ Can't act on that member (role hierarchy).")
    await member.kick(reason=reason)
    await ctx.send(embed=emb("👢 Kicked", f"{member} — {reason}", 0xED4245))
    await send_log(ctx.guild, "mod", "👢 Kick", f"{member} by {ctx.author.mention}: {reason}")


@mod.command(name="ban")
@commands.has_permissions(ban_members=True)
async def mod_ban(ctx, member: discord.Member, *, reason: str = "No reason"):
    if not can_act(ctx, member):
        return await ctx.send("❌ Can't act on that member (role hierarchy).")
    await member.ban(reason=reason)
    await ctx.send(embed=emb("🔨 Banned", f"{member} — {reason}", 0xED4245))


# ───────────────────────── setup commands ─────────────────────────
SETUP_KEYS = [("Core Antinuke", "antinuke"), ("SuperAntinuke", "superantinuke"),
              ("Raidmode", "raidmode"), ("AutoMod", "automod")]


def setup_embed(guild):
    d = gd(guild.id)
    e = emb("⚙️ Security Setup", "Click a button to toggle a module.")
    for label, key in SETUP_KEYS:
        e.add_field(name=label, value=onoff(d[key]["enabled"]))
    return e


class SetupView(discord.ui.View):
    def __init__(self, author_id, guild):
        super().__init__(timeout=300)
        self.author_id, self.guild = author_id, guild
        for label, key in SETUP_KEYS:
            self.add_item(self.make_btn(label, key))

    def make_btn(self, label, key):
        on = gd(self.guild.id)[key]["enabled"]
        b = discord.ui.Button(label=label, style=discord.ButtonStyle.success if on else discord.ButtonStyle.danger)

        async def cb(i: discord.Interaction):
            d = gd(self.guild.id)
            d[key]["enabled"] = not d[key]["enabled"]
            save()
            await i.response.edit_message(embed=setup_embed(self.guild), view=SetupView(self.author_id, self.guild))
        b.callback = cb
        return b

    async def interaction_check(self, i):
        if i.user.id != self.author_id:
            await i.response.send_message("Not your panel.", ephemeral=True)
            return False
        return True


@bot.command(aliases=["setupsecurity"])
@admin()
async def securitysetup(ctx):
    await ctx.send(embed=setup_embed(ctx.guild), view=SetupView(ctx.author.id, ctx.guild))


@bot.command()
@admin()
async def autosetup(ctx):
    async with ctx.typing():
        d = gd(ctx.guild.id)
        # Do not turn on Raidmode automatically: doing so can restrict every new
        # member immediately after setup. Admin must explicitly run !raidmode on.
        for key in ("antinuke", "superantinuke", "automod"):
            d[key]["enabled"] = True
        save()
        await setup_logs(ctx.guild)
        r, c = await take_snapshot(ctx.guild)
    await ctx.send(embed=emb("🛡️ Security Setup Complete",
                             "✅ Core Antinuke enabled\n✅ SuperAntinuke enabled\n✅ AutoMod enabled\n"
                             "⚪ Raidmode remains OFF until an admin enables it\n"
                             f"✅ Private logs configured\n✅ Snapshot saved ({r} roles, {c} channels)", 0x57F287))


# ───────────────────────── errors / startup ─────────────────────────
@bot.event
async def on_command_error(ctx, err):
    if isinstance(err, commands.CommandNotFound):
        return
    if isinstance(err, commands.MissingPermissions):
        return await ctx.send("❌ You don't have permission for that.")
    if isinstance(err, (commands.MissingRequiredArgument, commands.BadArgument)):
        return await ctx.send(f"❌ Wrong usage: {err}")
    if isinstance(err, commands.CommandInvokeError) and isinstance(err.original, discord.Forbidden):
        return await ctx.send("❌ I lack permission (move my role higher / give Administrator).")
    if isinstance(err, commands.NoPrivateMessage):
        return await ctx.send("❌ This command can only be used in a server.")
    if isinstance(err, commands.CommandInvokeError):
        original = err.original
        if isinstance(original, discord.Forbidden):
            return await ctx.send("❌ Missing Discord permission or role hierarchy is blocking this action.")
        if isinstance(original, discord.HTTPException):
            return await ctx.send("❌ Discord rejected the request. Please retry shortly.")
        log.exception("Command failed: %s", ctx.command, exc_info=original)
        return await ctx.send("❌ An internal error occurred; it has been logged.")
    log.warning("Unhandled command error: %r", err)


@bot.event
async def setup_hook():
    load()
    bot.add_view(TicketPanel())
    if not night_loop.is_running():
        night_loop.start()


@bot.event
async def on_ready():
    log.info("Logged in as %s | %s servers", bot.user, len(bot.guilds))
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching,
                                                        name="over your server | !help"))


# ───────────────────────── emergency panic lockdown ─────────────────────────
@bot.group(name="panic", invoke_without_command=True)
@commands.guild_only()
async def panic(ctx):
    state = gd(ctx.guild.id)["panic"]["enabled"]
    await ctx.send(embed=emb("🚨 Panic Mode", f"Status: {onoff(state)}\nUse `{gd(ctx.guild.id)['prefix']}panic on` or `off`.", 0xED4245 if state else COLOR))


@panic.command(name="on")
@commands.has_permissions(administrator=True)
async def panic_on(ctx):
    d = gd(ctx.guild.id)["panic"]
    if d["enabled"]:
        return await ctx.send("🚨 Panic Mode is already enabled.")
    saved = {}
    failed = 0
    for channel in ctx.guild.text_channels:
        try:
            overwrite = channel.overwrites_for(ctx.guild.default_role)
            saved[str(channel.id)] = overwrite.send_messages
            overwrite.send_messages = False
            await channel.set_permissions(ctx.guild.default_role, overwrite=overwrite,
                                          reason=f"Panic Mode activated by {ctx.author} ({ctx.author.id})")
            await asyncio.sleep(0.15)
        except (discord.Forbidden, discord.HTTPException):
            failed += 1
    d["overwrites"] = saved
    d["enabled"] = True
    save()
    await send_log(ctx.guild, "security", "🚨 Panic Mode Enabled", f"By {ctx.author} • channels failed: {failed}", 0xED4245)
    await ctx.send(embed=emb("🚨 Panic Mode Enabled", f"Locked {len(saved) - failed} text channels.\nFailed: {failed}\nUse `!panic off` after investigating.", 0xED4245))


@panic.command(name="off")
@commands.has_permissions(administrator=True)
async def panic_off(ctx):
    d = gd(ctx.guild.id)["panic"]
    if not d["enabled"]:
        return await ctx.send("Panic Mode is not enabled.")
    restored, failed = 0, 0
    for raw_id, previous in list(d["overwrites"].items()):
        channel = ctx.guild.get_channel(int(raw_id))
        if not isinstance(channel, discord.TextChannel):
            continue
        try:
            overwrite = channel.overwrites_for(ctx.guild.default_role)
            overwrite.send_messages = previous
            await channel.set_permissions(ctx.guild.default_role, overwrite=overwrite,
                                          reason=f"Panic Mode deactivated by {ctx.author} ({ctx.author.id})")
            restored += 1
            await asyncio.sleep(0.15)
        except (discord.Forbidden, discord.HTTPException):
            failed += 1
    d["overwrites"] = {}
    d["enabled"] = False
    save()
    await send_log(ctx.guild, "security", "🟢 Panic Mode Disabled", f"By {ctx.author} • restored: {restored} • failed: {failed}", 0x57F287)
    await ctx.send(embed=emb("🟢 Panic Mode Disabled", f"Restored saved send-message settings for {restored} channels. Failed: {failed}.", 0x57F287))


# ───────────────────────── chat lock / unlock ─────────────────────────

@bot.command(name="lock")
@commands.guild_only()
@commands.has_permissions(manage_channels=True)
async def lock_chat(ctx, channel: discord.TextChannel = None):
    channel = channel or ctx.channel

    if not channel.permissions_for(ctx.guild.me).manage_channels:
        return await ctx.send("❌ Bot ko Manage Channels permission chahiye.")

    overwrite = channel.overwrites_for(ctx.guild.default_role)
    overwrite.send_messages = False

    try:
        await channel.set_permissions(
            ctx.guild.default_role,
            overwrite=overwrite,
            reason=f"Chat locked by {ctx.author}"
        )
        await ctx.send(
            embed=emb(
                "🔒 Chat Locked",
                f"{channel.mention} mein @everyone ab message nahi bhej sakta.",
                0xED4245
            )
        )
    except discord.Forbidden:
        await ctx.send("❌ Bot ke paas required permission nahi hai.")
    except discord.HTTPException:
        await ctx.send("❌ Channel lock nahi ho paya.")


@bot.command(name="unlock")
@commands.guild_only()
@commands.has_permissions(manage_channels=True)
async def unlock_chat(ctx, channel: discord.TextChannel = None):
    channel = channel or ctx.channel

    if not channel.permissions_for(ctx.guild.me).manage_channels:
        return await ctx.send("❌ Bot ko Manage Channels permission chahiye.")

    overwrite = channel.overwrites_for(ctx.guild.default_role)
    overwrite.send_messages = None

    try:
        await channel.set_permissions(
            ctx.guild.default_role,
            overwrite=overwrite,
            reason=f"Chat unlocked by {ctx.author}"
        )
        await ctx.send(
            embed=emb(
                "🔓 Chat Unlocked",
                f"{channel.mention} ka chat permission default par reset kar diya gaya.",
                0x57F287
            )
        )
    except discord.Forbidden:
        await ctx.send("❌ Bot ke paas required permission nahi hai.")
    except discord.HTTPException:
        await ctx.send("❌ Channel unlock nahi ho paya.")


if not TOKEN or TOKEN.strip() in {"PASTE_TOKEN_HERE", "YOUR_BOT_TOKEN"}:
    raise RuntimeError("Set DISCORD_TOKEN in Railway Variables before starting Souvion Security.")

bot.run(TOKEN)
