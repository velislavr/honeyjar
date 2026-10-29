"""Raw-TCP honeypots that live next to the HTTP one: an unauthenticated Redis 5 and an
unsecured Android Debug Bridge (ADB) device, the two favourite targets of cryptojacking
and Mirai-style worms after SSH/Telnet.

Both speak just enough protocol for attack scripts to reach their payload stage. Nothing
received is executed, nothing is fetched, and no outbound connection is ever made
(`SLAVEOF` / `tcp:` forwards are acknowledged and ignored). Uploaded files are hashed
on the fly and discarded.
"""
import asyncio
import datetime as dt
import fnmatch
import hashlib
import secrets
import struct
from collections.abc import Callable

Log = Callable[[dict], None]

IDLE_TIMEOUT = 90
MAX_COMMANDS = 400
MAX_CLIENTS = 200


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _printable(b: bytes, limit: int = 4096) -> str:
    return b[:limit].decode("utf-8", "backslashreplace").replace("\x00", "\\x00")


class Service:
    """Shared connection bookkeeping: session id, logging, client cap."""

    name = ""

    def __init__(self, log: Log):
        self.log = log
        self.slots = asyncio.Semaphore(MAX_CLIENTS)

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if self.slots.locked():
            writer.close()
            return
        async with self.slots:
            peer = writer.get_extra_info("peername") or ("?", 0)
            sock = writer.get_extra_info("sockname") or ("?", 0)
            base = {"service": self.name, "src_ip": peer[0], "src_port": peer[1], "dst_port": sock[1],
                    "session": secrets.token_hex(6)}
            emit = lambda event, **kw: self.log({"ts": _now(), **base, "event": event, **kw})  # noqa: E731
            emit("connect")
            try:
                await asyncio.wait_for(self.session(reader, writer, emit), IDLE_TIMEOUT * 4)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, ValueError):
                pass
            finally:
                writer.close()

    async def session(self, reader, writer, emit):
        raise NotImplementedError


# ---------------------------------------------------------------- Redis

REDIS_INFO = """# Server
redis_version:5.0.7
redis_git_sha1:00000000
redis_mode:standalone
os:Linux 5.15.0-122-generic x86_64
arch_bits:64
gcc_version:9.3.0
process_id:1187
tcp_port:6379
uptime_in_seconds:3984211
uptime_in_days:46
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf

# Clients
connected_clients:3

# Memory
used_memory:2147384
used_memory_human:2.05M
maxmemory:0

# Persistence
rdb_last_save_time:1761700000
aof_enabled:0

# Replication
role:master
connected_slaves:0

# Keyspace
db0:keys={keys},expires=2,avg_ttl=0
"""
REDIS_BASE_KEYS = {b"session:9f2c41aa": b"{\"uid\":1001}", b"user:1001": b"admin@portal.local",
                   b"cache:homepage": b"<html>...</html>", b"queue:emails": b"3"}
REDIS_CONFIG = {b"dir": b"/var/lib/redis", b"dbfilename": b"dump.rdb", b"requirepass": b"", b"maxmemory": b"0",
                b"appendonly": b"no", b"save": b"900 1 300 10 60 10000", b"bind": b"0.0.0.0", b"protected-mode": b"no"}


def bulk(v: bytes | None) -> bytes:
    return b"$-1\r\n" if v is None else b"$%d\r\n%s\r\n" % (len(v), v)


def array(items: list[bytes]) -> bytes:
    return b"*%d\r\n" % len(items) + b"".join(bulk(i) for i in items)


class Redis(Service):
    name = "redis"

    async def read_command(self, reader: asyncio.StreamReader) -> list[bytes] | None:
        line = await asyncio.wait_for(reader.readline(), IDLE_TIMEOUT)
        if not line:
            return None
        if line[:1] != b"*":  # inline command, e.g. from netcat or simple scanners
            return line.strip().split()
        n = int(line[1:].strip())
        if not 0 < n <= 64:
            raise ValueError("bad array")
        args = []
        for _ in range(n):
            hdr = await asyncio.wait_for(reader.readline(), IDLE_TIMEOUT)
            size = int(hdr[1:].strip())
            if hdr[:1] != b"$" or not 0 <= size <= 512 * 1024:
                raise ValueError("bad bulk")
            args.append((await asyncio.wait_for(reader.readexactly(size + 2), IDLE_TIMEOUT))[:-2])
        return args

    async def session(self, reader, writer, emit):
        store = dict(REDIS_BASE_KEYS)
        config = dict(REDIS_CONFIG)
        modules = False
        for _ in range(MAX_COMMANDS):
            args = await self.read_command(reader)
            if args is None:
                return
            if not args:
                continue
            cmd, rest = args[0].lower(), args[1:]
            if cmd == b"auth":
                user, pw = (rest[0], rest[1]) if len(rest) > 1 else (b"default", rest[0] if rest else b"")
                emit("login", username=_printable(user, 256), password=_printable(pw, 256), success=False)
                writer.write(b"-ERR AUTH <password> called without any password configured for the default user. "
                             b"Are you sure your configuration is correct?\r\n")
                await writer.drain()
                continue
            emit("command", command=_printable(b" ".join(args)))
            reply, close = self.reply(cmd, rest, store, config, modules)
            if cmd == b"module" and rest and rest[0].lower() == b"load":
                modules = True
            writer.write(reply)
            await writer.drain()
            if close:
                return

    def reply(self, cmd: bytes, rest: list[bytes], store: dict, config: dict, modules: bool) -> tuple[bytes, bool]:
        sub = rest[0].lower() if rest else b""
        if cmd == b"ping":
            return (bulk(rest[0]) if rest else b"+PONG\r\n"), False
        if cmd == b"echo":
            return bulk(rest[0] if rest else b""), False
        if cmd == b"quit":
            return b"+OK\r\n", True
        if cmd == b"info":
            return bulk(REDIS_INFO.format(keys=len(store)).replace("\n", "\r\n").encode()), False
        if cmd == b"config":
            if sub == b"get" and len(rest) > 1:
                pat = rest[1][:128].decode("latin-1").lower()  # glob, like Redis; never a regex from the attacker
                hits = [kv for k, v in config.items() if fnmatch.fnmatchcase(k.decode(), pat) for kv in (k, v)]
                return array(hits), False
            if sub == b"set" and len(rest) > 2:
                config[rest[1].lower()] = rest[2][:1024]
            return b"+OK\r\n", False
        if cmd == b"set" and len(rest) > 1:
            if len(store) < 256:
                store[rest[0][:256]] = rest[1][:64 * 1024]
            return b"+OK\r\n", False
        if cmd == b"get":
            return bulk(store.get(rest[0]) if rest else None), False
        if cmd in (b"del", b"unlink", b"exists"):
            n = sum(1 for k in rest if k in store)
            if cmd != b"exists":
                for k in rest:
                    store.pop(k, None)
            return b":%d\r\n" % n, False
        if cmd == b"keys":
            return array(list(store)), False
        if cmd == b"scan":
            return b"*2\r\n" + bulk(b"0") + array(list(store)), False
        if cmd == b"dbsize":
            return b":%d\r\n" % len(store), False
        if cmd in (b"flushall", b"flushdb"):
            store.clear()
            return b"+OK\r\n", False
        if cmd == b"type":
            return (b"+string\r\n" if rest and rest[0] in store else b"+none\r\n"), False
        if cmd == b"ttl":
            return b":-1\r\n", False
        if cmd == b"bgsave":
            return b"+Background saving started\r\n", False
        if cmd == b"lastsave":
            return b":1761700000\r\n", False
        if cmd in (b"select", b"save", b"slaveof", b"replicaof", b"client", b"readonly"):
            return b"+OK\r\n", False  # SLAVEOF is acknowledged, but no replication connection is ever opened
        if cmd == b"module":
            return (b"+OK\r\n" if sub == b"load" else b"*0\r\n"), False
        if cmd.startswith(b"system.") and modules:
            return bulk(b""), False  # a "loaded" exploit module: accept its commands, run nothing
        if cmd == b"eval":
            script = rest[0] if rest else b""
            # CVE-2022-0543 probes usually run `id` first; a believable answer draws out the second stage.
            if b"popen" in script and b'"id"' in script.replace(b"'", b'"'):
                return bulk(b"uid=0(root) gid=0(root) groups=0(root)\n"), False
            return bulk(None), False
        if cmd == b"command":
            return b"*0\r\n", False
        return b"-ERR unknown command `%s`, with args beginning with: \r\n" % cmd[:64], False


# ---------------------------------------------------------------- ADB

A_CNXN, A_OPEN, A_OKAY, A_CLSE, A_WRTE, A_AUTH = (
    0x4E584E43, 0x4E45504F, 0x59414B4F, 0x45534C43, 0x45545257, 0x48545541)
ADB_BANNER = (b"device::ro.product.name=gtaxlwifi;ro.product.model=SM-T580;ro.product.device=gtaxlwifi;"
              b"features=cmd,shell_v2\x00")
ADB_PROPS = {b"ro.product.model": b"SM-T580", b"ro.product.cpu.abi": b"arm64-v8a",
             b"ro.build.version.release": b"8.1.0", b"ro.product.name": b"gtaxlwifi"}
MAX_UPLOAD = 16 * 2**20


def adb_packet(cmd: int, arg0: int, arg1: int, data: bytes = b"") -> bytes:
    return struct.pack("<6I", cmd, arg0, arg1, len(data), sum(data) & 0xFFFFFFFF, cmd ^ 0xFFFFFFFF) + data


def shell_output(command: bytes) -> bytes:
    """Plausible output for the handful of commands worms use to fingerprint a device."""
    c = command.strip()
    if c.startswith(b"getprop"):
        key = c.split()[1] if len(c.split()) > 1 else b""
        return ADB_PROPS.get(key, b"") + b"\n"
    if c in (b"id", b"whoami"):
        return b"uid=2000(shell) gid=2000(shell) groups=2000(shell),1004(input),1007(log)\n" if c == b"id" else b"shell\n"
    if c.startswith(b"echo "):
        return c[5:].strip(b"'\"") + b"\n"
    if c.startswith(b"uname"):
        return b"Linux localhost 4.4.111-15211808 #1 SMP PREEMPT Mon Jan 21 15:24:54 KST 2019 aarch64\n"
    return b""


class Adb(Service):
    name = "adb"

    async def read_packet(self, reader) -> tuple[int, int, int, bytes]:
        hdr = await asyncio.wait_for(reader.readexactly(24), IDLE_TIMEOUT)
        cmd, arg0, arg1, length, _check, magic = struct.unpack("<6I", hdr)
        if magic != cmd ^ 0xFFFFFFFF or length > 1024 * 1024:
            raise ValueError("bad adb packet")
        return cmd, arg0, arg1, await asyncio.wait_for(reader.readexactly(length), IDLE_TIMEOUT)

    async def session(self, reader, writer, emit):
        next_id = 1
        streams: dict[int, dict] = {}  # our id -> {"remote", "kind", "buf", "hash", ...}
        for _ in range(MAX_COMMANDS * 4):
            cmd, arg0, arg1, data = await self.read_packet(reader)
            if cmd == A_CNXN:
                writer.write(adb_packet(A_CNXN, 0x01000000, 4096, ADB_BANNER))
            elif cmd == A_OPEN:
                service = data.rstrip(b"\x00")
                local, next_id = next_id, next_id + 1
                if service.startswith(b"shell:"):
                    command = service[6:]
                    emit("command", command=_printable(command) if command else "shell")
                    writer.write(adb_packet(A_OKAY, local, arg0))
                    if command:  # one-shot `adb shell <cmd>`
                        out = shell_output(command)
                        if out:
                            writer.write(adb_packet(A_WRTE, local, arg0, out))
                        writer.write(adb_packet(A_CLSE, local, arg0))
                    else:  # interactive shell: commands arrive as WRTE lines
                        streams[local] = {"remote": arg0, "kind": "shell", "buf": b""}
                        writer.write(adb_packet(A_WRTE, local, arg0, b"gtaxlwifi:/ $ "))
                elif service.startswith(b"sync:"):
                    streams[local] = {"remote": arg0, "kind": "sync", "buf": b"", "path": None,
                                      "hash": hashlib.sha256(), "size": 0}
                    writer.write(adb_packet(A_OKAY, local, arg0))
                else:  # tcp:, reverse:, jdwp:, ... are refused; nothing is ever forwarded
                    emit("command", command=_printable(service))
                    writer.write(adb_packet(A_CLSE, 0, arg0))
            elif cmd == A_WRTE and arg1 in streams:
                st = streams[arg1]
                writer.write(adb_packet(A_OKAY, arg1, st["remote"]))
                if st["kind"] == "shell":
                    st["buf"] += data
                    while b"\n" in st["buf"]:
                        line, st["buf"] = st["buf"].split(b"\n", 1)
                        if line.strip():
                            emit("command", command=_printable(line.strip()))
                            writer.write(adb_packet(A_WRTE, arg1, st["remote"], shell_output(line) + b"gtaxlwifi:/ $ "))
                else:
                    reply = self.sync(st, data, emit)
                    if reply:
                        writer.write(adb_packet(A_WRTE, arg1, st["remote"], reply))
            elif cmd == A_CLSE and arg1 in streams:
                writer.write(adb_packet(A_CLSE, arg1, streams.pop(arg1)["remote"]))
            await writer.drain()

    @staticmethod
    def sync(st: dict, data: bytes, emit) -> bytes:
        """Follow the `adb push` sync sub-protocol (SEND path / DATA chunks / DONE): hash, never store."""
        st["buf"] += data
        reply = b""
        while len(st["buf"]) >= 8:
            tag, n = st["buf"][:4], struct.unpack("<I", st["buf"][4:8])[0]
            if tag == b"DONE":
                st["buf"] = st["buf"][8:]
                emit("download", sha256=st["hash"].hexdigest(), size=st["size"],
                     path=_printable(st["path"] or b"?", 512), command=f"adb push {_printable(st['path'] or b'?', 512)}")
                st.update(hash=hashlib.sha256(), size=0)
                reply += b"OKAY" + struct.pack("<I", 0)
                continue
            if tag == b"QUIT":
                st["buf"] = b""
                break
            if len(st["buf"]) < 8 + n:
                if tag == b"DATA" and n > 64 * 1024:
                    raise ValueError("oversized chunk")
                break
            body, st["buf"] = st["buf"][8:8 + n], st["buf"][8 + n:]
            if tag == b"SEND":
                st["path"] = body.split(b",")[0]
            elif tag == b"DATA" and st["size"] < MAX_UPLOAD:
                st["hash"].update(body)
                st["size"] += len(body)
            elif tag in (b"STAT", b"LIST"):
                reply += (b"STAT" + b"\x00" * 12) if tag == b"STAT" else (b"DONE" + b"\x00" * 16)
        return reply


async def start(log: Log, redis_ports: list[int], adb_ports: list[int]) -> list[asyncio.Server]:
    servers = []
    for ports, svc in ((redis_ports, Redis(log)), (adb_ports, Adb(log))):
        for port in ports:
            servers.append(await asyncio.start_server(svc.serve, "0.0.0.0", port, limit=600 * 1024))
    return servers
