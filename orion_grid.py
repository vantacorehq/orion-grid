#!/usr/bin/env python3
"""
ORION-GRID  --  Decentralized P2P compute cluster for autonomous AI agents.
One file. Zero dependencies (Python >= 3.9 standard library only).

Subcommands:  keygen | serve | submit | bench      (see --help / README.md)

Wire protocol (v1)
  Handshake : 3 raw length-prefixed JSON frames, mutual HMAC-SHA256 proofs over
              fresh nonces (cluster secret never leaves the process).
  Session   : [u32 len][32B MAC][JSON body].  MAC = HMAC-SHA256(rolling_key,
              seq || body); after every frame rolling_key = SHA256(rolling_key||MAC).
              Replayed, reordered, forged or truncated frames fail verification and
              the connection is dropped immediately.
"""
from __future__ import annotations

import argparse, asyncio, hashlib, hmac, json, os, random, re, secrets
import signal, struct, sys, time
from collections import OrderedDict
from math import isqrt

__version__ = "1.0.0"
PROTO = 1
MAX_FRAME = 1 << 20            # 1 MiB hard cap per frame
MAC_LEN = 32
HS_TIMEOUT = 5.0               # handshake deadline (s)
SEND_TIMEOUT = 5.0             # slow-consumer deadline (s) -> peer is pruned
DEFAULT_TTL = 8
SEEN_CAP = 65536
ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_HDR, _SEQ = struct.Struct(">I"), struct.Struct(">Q")


def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


class AuthError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Telemetry (O(1) integer ops on the event loop; never blocks, never locks)
# --------------------------------------------------------------------------- #
class Telemetry:
    def __init__(self) -> None:
        self.tx = self.rx = self.routed = self.auth_drops = 0
        self.originated = self.executed = self.pruned = self.sync_timeouts = 0
        self.lat_n = 0
        self.lat_last = self.lat_sum = self.lat_max = 0.0
        self.lat_min = float("inf")
        self.started = time.monotonic()

    def record_latency(self, s: float) -> None:
        self.lat_n += 1
        self.lat_last = s
        self.lat_sum += s
        self.lat_max = max(self.lat_max, s)
        self.lat_min = min(self.lat_min, s)

    def snapshot(self, node: "Node") -> dict:
        f = lambda x: f"{x:.6f}"
        return {
            "node_id": node.id,
            "routed_p2p_packets": self.routed,
            "total_active_compute_nodes": len(node.peers) + (1 if node.compute else 0),
            "cluster_sync_latency_s": {
                "last": f(self.lat_last),
                "avg": f(self.lat_sum / self.lat_n if self.lat_n else 0.0),
                "min": f(self.lat_min if self.lat_n else 0.0),
                "max": f(self.lat_max),
                "samples": self.lat_n,
            },
            "packets_tx": self.tx, "packets_rx": self.rx,
            "auth_drops": self.auth_drops, "peers_pruned": self.pruned,
            "events_originated": self.originated, "events_executed": self.executed,
            "sync_timeouts": self.sync_timeouts,
            "uptime_s": f(time.monotonic() - self.started),
        }

    def line(self, node: "Node") -> str:
        s = self.snapshot(node)
        L = s["cluster_sync_latency_s"]
        return (f"[orion] node={node.id} nodes={s['total_active_compute_nodes']} "
                f"routed={s['routed_p2p_packets']} tx={self.tx} rx={self.rx} "
                f"auth_drops={self.auth_drops} pruned={self.pruned} "
                f"sync_last={L['last']}s sync_avg={L['avg']}s sync_max={L['max']}s")


# --------------------------------------------------------------------------- #
# Built-in compute handlers (strictly whitelisted -- no remote code execution)
# --------------------------------------------------------------------------- #
def prime_count(lo: int, hi: int) -> int:
    """Count primes in [lo, hi) with a segmented sieve."""
    lo = max(lo, 2)
    if hi <= lo:
        return 0
    r = isqrt(hi - 1) + 1
    base = bytearray([1]) * (r + 1)
    base[0:2] = b"\x00\x00"
    for i in range(2, isqrt(r) + 1):
        if base[i]:
            base[i * i::i] = bytearray(len(range(i * i, r + 1, i)))
    seg = bytearray([1]) * (hi - lo)
    for p in range(2, r + 1):
        if base[p]:
            start = max(p * p, ((lo + p - 1) // p) * p)
            if start < hi:
                seg[start - lo::p] = bytearray(len(range(start - lo, hi - lo, p)))
    return sum(seg)


def _h_compute(payload: dict, node_id: str):
    job = payload.get("job")
    args = payload["assign"].get(node_id) if "assign" in payload else payload.get("args")
    if args is None:
        return {"skipped": True}
    if job == "prime_count":
        lo, hi = int(args[0]), int(args[1])
        if not (0 <= lo <= hi <= 10**12) or hi - lo > 20_000_000:
            raise ValueError("range out of bounds (max span 20,000,000)")
        return prime_count(lo, hi)
    if job == "hash_chain":
        seed, iters = str(args[0]).encode(), int(args[1])
        if not 0 <= iters <= 20_000_000:
            raise ValueError("iters out of bounds")
        h = seed
        for _ in range(iters):
            h = hashlib.sha256(h).digest()
        return h.hex()
    raise ValueError(f"unknown job {job!r}")


async def _h_echo(node: "Node", payload: dict):
    return {"len": len(str(payload.get("data", "")))}


async def _h_mask_rules(node: "Node", payload: dict):
    """Versioned token-masking rule set; newest version wins cluster-wide."""
    ver = int(payload.get("version", 0))
    if ver <= node.mask_version:
        return {"applied": False, "version": node.mask_version}
    rules = []
    for r in list(payload.get("rules", []))[:64]:
        pat = str(r["pattern"])
        if len(pat) <= 256:
            rules.append((re.compile(pat), str(r.get("repl", "[MASKED]"))[:64]))
    node.mask_rules, node.mask_version = rules, ver
    return {"applied": True, "version": ver, "rules": len(rules)}


async def _h_prompt(node: "Node", payload: dict):
    """Deterministic prompt pipeline: strip|lower|upper|collapse_ws|mask|truncate:N|sha."""
    text = str(payload.get("text", ""))[:100_000]
    for st in list(payload.get("stages", []))[:32]:
        st = str(st)
        if st == "strip": text = text.strip()
        elif st == "lower": text = text.lower()
        elif st == "upper": text = text.upper()
        elif st == "collapse_ws": text = " ".join(text.split())
        elif st == "mask":
            for rx, repl in node.mask_rules:
                text = rx.sub(repl, text)
        elif st.startswith("truncate:"): text = text[: max(0, int(st[9:]))]
        else: raise ValueError(f"unknown stage {st!r}")
    return {"text": text[:2000], "len": len(text),
            "sha256": hashlib.sha256(text.encode()).hexdigest()}


# --------------------------------------------------------------------------- #
# Peer / pending-collection helpers
# --------------------------------------------------------------------------- #
class Peer:
    __slots__ = ("id", "addr", "reader", "writer", "tx_key", "rx_key", "tx_seq",
                 "rx_seq", "lock", "last_rx", "rtt", "initiator")

    def __init__(self, pid, addr, reader, writer, tx_key, rx_key, initiator):
        self.id, self.addr, self.reader, self.writer = pid, addr, reader, writer
        self.tx_key, self.rx_key, self.tx_seq, self.rx_seq = tx_key, rx_key, 0, 0
        self.lock = asyncio.Lock()
        self.last_rx = time.monotonic()
        self.rtt = 0.0
        self.initiator = initiator


class _Pending:
    def __init__(self, expected: set, expect_count: int | None):
        self.expected, self.expect_count = expected, expect_count
        self.results: dict = {}
        self.t_last = 0.0
        self.event = asyncio.Event()

    def add(self, nid: str, res) -> None:
        self.results[nid] = res
        self.t_last = time.perf_counter()
        self.event.set()

    def _done(self, live: set) -> bool:
        if self.expect_count is not None:
            return len(self.results) >= self.expect_count or not live
        return not ((self.expected & live) - set(self.results))

    async def wait(self, node: "Node", timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            self.event.clear()
            if self._done(set(node.peers)):
                return True
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            try:
                await asyncio.wait_for(self.event.wait(), left)
            except asyncio.TimeoutError:
                return False


# --------------------------------------------------------------------------- #
# Node
# --------------------------------------------------------------------------- #
class Node:
    def __init__(self, host="0.0.0.0", port=7777, secret="", seeds=(), node_id=None,
                 max_peers=32, mesh=True, compute=True, workers=0, max_inflight=8,
                 hb_interval=2.0, dead_after=8.0, dial_interval=1.0):
        if not secret:
            raise ValueError("a cluster secret is required")
        self.secret = _sha(b"orion-grid/v1/" + secret.encode())
        self.id = node_id or secrets.token_hex(6)
        if not ID_RE.match(self.id):
            raise ValueError("invalid node id")
        self.host, self.port = host, port
        self.max_peers, self.mesh, self.compute, self.workers = max_peers, mesh, compute, workers
        self.hb_interval, self.dead_after, self.dial_interval = hb_interval, dead_after, dial_interval
        self.peers: dict[str, Peer] = {}
        self.known: dict[tuple, dict] = {}
        self.seeds = set(tuple(s) for s in seeds)
        self.dialing: set = set()
        self.seen: OrderedDict = OrderedDict()
        self.pending: dict[str, _Pending] = {}
        self.tele = Telemetry()
        self.mask_rules: list = []
        self.mask_version = 0
        self.handlers: dict = {
            "compute": (_h_compute, True), "echo": (_h_echo, False),
            "mask_rules": (_h_mask_rules, False), "prompt_pipeline": (_h_prompt, False)}
        self._server = None
        self._tasks: set = set()
        self._sem = asyncio.Semaphore(max_inflight)
        self._pool = None
        for s in self.seeds:
            self.known[s] = {"fails": 0, "next": 0.0}

    # ---- public API ------------------------------------------------------- #
    def register(self, kind: str, fn, blocking: bool = False) -> None:
        """blocking=False: async fn(node, payload). blocking=True: sync fn(payload, node_id)
        run in an executor (process pool if workers>0, must then be module-level/picklable)."""
        self.handlers[kind] = (fn, blocking)

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._on_inbound, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        for coro in (self._connector(), self._heartbeat()):
            self._spawn(coro)

    async def stop(self) -> None:
        for t in list(self._tasks):
            t.cancel()
        for p in list(self.peers.values()):
            self._drop(p)
        if self._server:
            self._server.close()
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)

    def start_reporter(self, interval: float) -> None:
        async def rep():
            while True:
                await asyncio.sleep(interval)
                print(self.tele.line(self), file=sys.stderr, flush=True)
        self._spawn(rep())

    async def wait_for_peers(self, n: int, timeout: float = 15.0) -> bool:
        end = time.monotonic() + timeout
        while len(self.peers) < n:
            if time.monotonic() > end:
                return False
            await asyncio.sleep(0.05)
        return True

    async def broadcast_event(self, kind: str, payload: dict, ttl: int = DEFAULT_TTL,
                              collect: bool = True, timeout: float = 10.0,
                              expect: int | None = None) -> dict:
        """Fan-out an event to every live peer; peers re-fan-out (TTL-bounded, de-duplicated).
        With collect=True, waits for acks and records cluster synchronization latency."""
        eid = secrets.token_hex(8)
        ev = {"eid": eid, "o": self.id, "k": kind, "p": payload, "ttl": int(ttl)}
        self._mark_seen(eid, None)
        targets = list(self.peers.values())
        pend = None
        if collect:
            pend = _Pending({p.id for p in targets}, expect)
            self.pending[eid] = pend
        self.tele.originated += 1
        t0 = time.perf_counter()
        local = asyncio.ensure_future(self._execute(ev))
        await self._fanout({"t": "ev", "e": ev}, targets)
        if not collect:
            self._tasks.add(local); local.add_done_callback(self._tasks.discard)
            return {"eid": eid, "sent": len(targets)}
        t_fan = time.perf_counter()
        try:
            complete = await pend.wait(self, timeout)
            local_res = await local
        finally:
            self.pending.pop(eid, None)
        if complete:
            latency = (pend.t_last if pend.results else t_fan) - t0
            self.tele.record_latency(latency)
        else:
            latency = None
            self.tele.sync_timeouts += 1
        return {"eid": eid, "complete": complete,
                "latency_s": None if latency is None else f"{latency:.6f}",
                "latency": latency, "local": local_res, "acks": pend.results}

    async def scatter_primes(self, lo: int, hi: int, timeout: float = 120.0) -> dict:
        """Shard [lo,hi) across self (if compute) + direct peers and sum the partial counts."""
        ids = sorted(([self.id] if self.compute else []) + list(self.peers))
        if not ids:
            raise RuntimeError("no compute nodes available")
        step = -(-(hi - lo) // len(ids))
        assign = {n: [lo + i * step, min(hi, lo + (i + 1) * step)] for i, n in enumerate(ids)}
        res = await self.broadcast_event("compute", {"job": "prime_count", "assign": assign},
                                         ttl=1, timeout=timeout)
        parts = {self.id: res["local"], **res["acks"]}
        total = sum(r["r"] for r in parts.values() if isinstance(r, dict) and r.get("ok") and isinstance(r.get("r"), int))
        res["total_primes"] = total
        res["shards"] = len(ids)
        return res

    # ---- plumbing --------------------------------------------------------- #
    def _spawn(self, coro) -> asyncio.Task:
        t = asyncio.ensure_future(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)
        return t

    def _mark_seen(self, eid: str, src) -> None:
        self.seen[eid] = src
        if len(self.seen) > SEEN_CAP:
            self.seen.popitem(last=False)

    def _drop(self, p: Peer, pruned: bool = False) -> None:
        if self.peers.get(p.id) is p:
            del self.peers[p.id]
            if pruned:
                self.tele.pruned += 1
            for pd in self.pending.values():
                pd.event.set()
        try:
            p.writer.close()
        except Exception:
            pass

    def _register(self, p: Peer) -> bool:
        old = self.peers.get(p.id)
        if old is not None:
            if old.initiator < p.initiator:       # deterministic tie-break, both sides agree
                return False
            self._drop(old)
        elif len(self.peers) >= self.max_peers:
            return False
        self.peers[p.id] = p
        return True

    # ---- handshake -------------------------------------------------------- #
    @staticmethod
    async def _write_raw(w, obj) -> None:
        d = json.dumps(obj, separators=(",", ":")).encode()
        w.write(_HDR.pack(len(d)) + d)
        await w.drain()

    @staticmethod
    async def _read_raw(r) -> dict:
        n = _HDR.unpack(await r.readexactly(4))[0]
        if n > 4096:
            raise AuthError("oversized handshake")
        return json.loads(await r.readexactly(n))

    def _keys(self, na: bytes, nb: bytes):
        return _mac(self.secret, b"K1" + na + nb), _mac(self.secret, b"K2" + na + nb)

    async def _on_inbound(self, r, w) -> None:
        peer = None
        try:
            hello = await asyncio.wait_for(self._read_raw(r), HS_TIMEOUT)
            pid, na, port = str(hello["id"]), bytes.fromhex(hello["na"]), int(hello.get("port", 0))
            if pid == self.id:                 # node dialed its own advertised address
                w.close()
                return
            if hello.get("v") != PROTO or len(na) != 16 or not ID_RE.match(pid):
                raise AuthError("bad hello")
            nb = os.urandom(16)
            proof = _mac(self.secret, b"R" + na + nb + self.id.encode() + pid.encode())
            await self._write_raw(w, {"id": self.id, "nb": nb.hex(), "proof": proof.hex()})
            auth = await asyncio.wait_for(self._read_raw(r), HS_TIMEOUT)
            want = _mac(self.secret, b"I" + nb + na + pid.encode() + self.id.encode())
            if not hmac.compare_digest(bytes.fromhex(auth["proof"]), want):
                raise AuthError("bad proof")
            k1, k2 = self._keys(na, nb)
            host = (w.get_extra_info("peername") or ("", 0))[0]
            peer = Peer(pid, (host, port) if port else None, r, w, k2, k1, initiator=pid)
        except (AuthError, KeyError, ValueError, TypeError):
            self.tele.auth_drops += 1          # forged / malformed handshake = rogue node
            w.close()
            return
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, OSError):
            w.close()                          # benign: self-dial, port scan, network blip
            return
        if not self._register(peer):
            w.close()
            return
        await self._serve_peer(peer)

    async def _dial(self, addr: tuple) -> str:
        r, w = await asyncio.wait_for(asyncio.open_connection(*addr), HS_TIMEOUT)
        try:
            na = os.urandom(16)
            await self._write_raw(w, {"v": PROTO, "id": self.id, "na": na.hex(), "port": self.port})
            resp = await asyncio.wait_for(self._read_raw(r), HS_TIMEOUT)
            pid, nb = str(resp["id"]), bytes.fromhex(resp["nb"])
            if pid == self.id:
                w.close()
                return "self"
            want = _mac(self.secret, b"R" + na + nb + pid.encode() + self.id.encode())
            if not ID_RE.match(pid) or not hmac.compare_digest(bytes.fromhex(resp["proof"]), want):
                raise AuthError("server failed proof")
            proof = _mac(self.secret, b"I" + nb + na + self.id.encode() + pid.encode())
            await self._write_raw(w, {"proof": proof.hex()})
            k1, k2 = self._keys(na, nb)
            peer = Peer(pid, addr, r, w, k1, k2, initiator=self.id)
        except Exception:
            w.close()
            raise
        if not self._register(peer):
            w.close()
            return "dup"
        self._spawn(self._serve_peer(peer))
        return "ok"

    # ---- framed, authenticated transport ---------------------------------- #
    async def _send(self, p: Peer, msg: dict) -> bool:
        body = json.dumps(msg, separators=(",", ":")).encode()
        if len(body) + MAC_LEN > MAX_FRAME:
            return False
        try:
            async with p.lock:                       # keeps the rolling chain ordered
                mac = _mac(p.tx_key, _SEQ.pack(p.tx_seq) + body)
                p.tx_key, p.tx_seq = _sha(p.tx_key + mac), p.tx_seq + 1
                p.writer.write(_HDR.pack(len(body) + MAC_LEN) + mac + body)
                await asyncio.wait_for(p.writer.drain(), SEND_TIMEOUT)
            self.tele.tx += 1
            return True
        except (OSError, asyncio.TimeoutError, RuntimeError):
            self._drop(p, pruned=True)
            return False

    async def _recv(self, p: Peer) -> dict:
        n = _HDR.unpack(await p.reader.readexactly(4))[0]
        if not MAC_LEN + 2 <= n <= MAX_FRAME:
            self.tele.auth_drops += 1
            raise AuthError("bad frame length")
        data = await p.reader.readexactly(n)
        mac, body = data[:MAC_LEN], data[MAC_LEN:]
        if not hmac.compare_digest(mac, _mac(p.rx_key, _SEQ.pack(p.rx_seq) + body)):
            self.tele.auth_drops += 1
            raise AuthError("rolling MAC mismatch")
        p.rx_key, p.rx_seq = _sha(p.rx_key + mac), p.rx_seq + 1
        p.last_rx = time.monotonic()
        self.tele.rx += 1
        return json.loads(body)

    async def _fanout(self, msg: dict, targets, count_routed: bool = False) -> None:
        if targets:
            await asyncio.gather(*(self._send(p, msg) for p in targets))
            if count_routed:
                self.tele.routed += len(targets)

    async def _serve_peer(self, p: Peer) -> None:
        try:
            await self._send(p, {"t": "peers", "l": self._peer_list()})
            while True:
                await self._dispatch(p, await self._recv(p))
        except (AuthError, asyncio.IncompleteReadError, OSError, asyncio.TimeoutError,
                ValueError, KeyError, TypeError, AttributeError, RuntimeError):
            pass
        finally:
            self._drop(p)

    def _peer_list(self) -> list:
        return [list(p.addr) for p in self.peers.values() if p.addr][:64]

    async def _dispatch(self, p: Peer, m: dict) -> None:
        t = m["t"]
        if t == "ping":
            await self._send(p, {"t": "pong", "s": m["s"]})
        elif t == "pong":
            p.rtt = time.perf_counter() - float(m["s"])
        elif t == "peers":
            for h, port in list(m["l"])[:64]:
                a = (str(h), int(port))
                if len(self.known) < 1024:
                    self.known.setdefault(a, {"fails": 0, "next": 0.0})
        elif t == "ev":
            e = m["e"]
            if not (isinstance(e["eid"], str) and len(e["eid"]) <= 64 and isinstance(e["k"], str)):
                raise ValueError("bad event")
            if e["eid"] not in self.seen:
                self._mark_seen(e["eid"], p.id)
                self._spawn(self._on_event(p, e))
        elif t == "ack":
            await self._on_ack(m)
        else:
            raise ValueError("unknown message type")

    # ---- event propagation / execution ------------------------------------ #
    async def _on_event(self, src: Peer, e: dict) -> None:
        ttl = min(int(e.get("ttl", 1)), 16) - 1
        if ttl > 0:                                   # fan-out first, execute second
            nxt = {"t": "ev", "e": {**e, "ttl": ttl}}
            await self._fanout(nxt, [q for q in self.peers.values() if q is not src], True)
        res = await self._execute(e)
        await self._send(src, {"t": "ack", "eid": e["eid"], "n": self.id, "r": res})

    async def _on_ack(self, m: dict) -> None:
        eid = m["eid"]
        if eid not in self.seen:
            return
        up = self.seen[eid]
        if up is None:
            pd = self.pending.get(eid)
            if pd:
                pd.add(str(m["n"]), m["r"])
        else:
            q = self.peers.get(up)
            if q:
                self.tele.routed += 1
                await self._send(q, m)

    async def _execute(self, e: dict):
        h = self.handlers.get(e["k"])
        if h is None or not self.compute:
            return {"ok": True, "skipped": True}
        fn, blocking = h
        async with self._sem:
            t = time.perf_counter()
            try:
                if blocking:
                    loop = asyncio.get_running_loop()
                    if self.workers and self._pool is None:
                        from concurrent.futures import ProcessPoolExecutor
                        self._pool = ProcessPoolExecutor(self.workers)
                    r = await loop.run_in_executor(self._pool, fn, e["p"], self.id)
                else:
                    r = await fn(self, e["p"])
                out = {"ok": True, "r": r, "ms": round((time.perf_counter() - t) * 1e3, 3)}
            except Exception as ex:                  # handler faults never kill the node
                out = {"ok": False, "err": f"{type(ex).__name__}: {ex}"[:200]}
            self.tele.executed += 1
        if len(json.dumps(out)) > 60_000:
            out = {"ok": True, "truncated": True}
        return out

    # ---- discovery / fault tolerance -------------------------------------- #
    async def _connector(self) -> None:
        while True:
            now = time.monotonic()
            connected = {p.addr for p in self.peers.values() if p.addr}
            for addr, st in list(self.known.items()):
                if (addr in connected or addr in self.dialing or st["next"] > now
                        or len(self.peers) + len(self.dialing) >= self.max_peers
                        or (not self.mesh and addr not in self.seeds)):
                    continue
                self.dialing.add(addr)
                self._spawn(self._try_dial(addr, st))
            await asyncio.sleep(self.dial_interval)

    async def _try_dial(self, addr: tuple, st: dict) -> None:
        try:
            r = await self._dial(addr)
            st["fails"] = 0
            st["next"] = time.monotonic() + (1e9 if r == "self" else 30 if r == "dup" else 1.0)
        except Exception:
            st["fails"] += 1
            st["next"] = time.monotonic() + min(60.0, 0.5 * 2 ** st["fails"]) * (0.8 + 0.4 * random.random())
        finally:
            self.dialing.discard(addr)

    async def _heartbeat(self) -> None:
        n = 0
        while True:
            await asyncio.sleep(self.hb_interval)
            now = time.monotonic()
            for p in list(self.peers.values()):
                if now - p.last_rx > self.dead_after:
                    self._drop(p, pruned=True)        # dead-peer pruning
            live = list(self.peers.values())
            await self._fanout({"t": "ping", "s": time.perf_counter()}, live)
            n += 1
            if n % 5 == 0:
                await self._fanout({"t": "peers", "l": self._peer_list()}, live)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _addr(s: str) -> tuple:
    h, _, p = s.rpartition(":")
    return (h or "127.0.0.1", int(p))


def _secret(a) -> str:
    s = a.secret or os.environ.get("ORION_SECRET", "")
    if a.secret_file:
        s = open(a.secret_file).read().strip()
    if not s:
        sys.exit("error: set --secret, --secret-file or $ORION_SECRET (generate one: orion_grid.py keygen)")
    return s


def _pct(xs: list, q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


async def _serve(a) -> None:
    node = Node(a.host, a.port, _secret(a), [_addr(s) for s in a.seed], a.id, a.max_peers,
                not a.no_mesh, True, a.workers)
    await node.start()
    print(f"[orion] node {node.id} listening on {node.host}:{node.port} seeds={len(node.seeds)}",
          file=sys.stderr, flush=True)
    if a.stats_interval > 0:
        node.start_reporter(a.stats_interval)
    stop = asyncio.Event()
    for sg in (signal.SIGINT, signal.SIGTERM):
        try:
            asyncio.get_running_loop().add_signal_handler(sg, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()
    print(json.dumps(node.tele.snapshot(node), indent=2))
    await node.stop()


async def _submit(a) -> None:
    node = Node("127.0.0.1", 0, _secret(a), [_addr(s) for s in a.seed], compute=False, max_peers=64)
    await node.start()
    try:
        if not await node.wait_for_peers(1, a.wait):
            sys.exit("error: could not join cluster (check seed and secret)")
        await asyncio.sleep(1.5)                       # let PEX settle into a mesh
        if a.job == "primes":
            out = await node.scatter_primes(a.lo, a.hi)
        elif a.job == "hash":
            out = await node.broadcast_event("compute", {"job": "hash_chain", "args": ["orion", a.iters]}, timeout=a.timeout)
        elif a.job == "prompt":
            out = await node.broadcast_event("prompt_pipeline", {"text": a.text, "stages": a.stages.split(",")}, timeout=a.timeout)
        else:
            out = await node.broadcast_event("echo", {"data": "ping"}, timeout=a.timeout)
        out.pop("latency", None)
        print(json.dumps({**out, "telemetry": node.tele.snapshot(node)}, indent=2))
    finally:
        await node.stop()


async def _bench(a) -> None:
    sec, nodes = "bench-" + secrets.token_hex(4), []
    for i in range(a.nodes):
        seeds = [("127.0.0.1", a.base_port)] if (i and a.topology == "mesh") else \
                [("127.0.0.1", a.base_port + i - 1)] if i else []
        n = Node("127.0.0.1", a.base_port + i, sec, seeds, f"n{i:02d}", a.nodes + 4,
                 a.topology == "mesh", True, 0, hb_interval=2.0, dial_interval=0.2)
        await n.start()
        nodes.append(n)
    want = a.nodes - 1 if a.topology == "mesh" else 1
    t0 = time.perf_counter()
    for n in nodes:
        if not await n.wait_for_peers(want if a.topology == "mesh" else 1, 20):
            sys.exit("bench: cluster failed to converge")
    conv = time.perf_counter() - t0
    data = "x" * a.payload_bytes
    ttl = a.nodes if a.topology == "line" else 3
    origin = nodes[0]
    for _ in range(5):                                  # warm-up
        await origin.broadcast_event("echo", {"data": data}, ttl=ttl, expect=a.nodes - 1)
    base = [(n.tele.routed, n.tele.tx, n.tele.rx) for n in nodes]
    lats, to = [], 0
    T0 = time.perf_counter()
    for _ in range(a.events):
        r = await origin.broadcast_event("echo", {"data": data}, ttl=ttl, expect=a.nodes - 1, timeout=10)
        if r["complete"]:
            lats.append(r["latency"])
        else:
            to += 1
    el = time.perf_counter() - T0
    routed = sum(n.tele.routed - b[0] for n, b in zip(nodes, base))
    pk = sum(n.tele.tx - b[1] for n, b in zip(nodes, base))
    print(f"ORION-GRID bench  nodes={a.nodes} topology={a.topology} events={a.events} payload={a.payload_bytes}B")
    print(f"  mesh convergence        : {conv:.6f} s")
    if lats:
        print(f"  sync latency  p50       : {_pct(lats, .50):.6f} s")
        print(f"  sync latency  p95       : {_pct(lats, .95):.6f} s")
        print(f"  sync latency  p99       : {_pct(lats, .99):.6f} s")
        print(f"  sync latency  max       : {max(lats):.6f} s")
    print(f"  throughput              : {len(lats) / el:.1f} cluster-wide syncs/s")
    print(f"  routed P2P packets      : {routed}")
    print(f"  total packets sent      : {pk}")
    print(f"  timeouts / auth drops   : {to} / {sum(n.tele.auth_drops for n in nodes)}")
    print(f"  active compute nodes    : {len(origin.peers) + 1} (direct view of origin)")
    for n in nodes:
        await n.stop()


def main() -> None:
    ap = argparse.ArgumentParser(prog="orion_grid.py", description=__doc__.split("\n")[1])
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def sec(p):
        p.add_argument("--secret"); p.add_argument("--secret-file")

    sub.add_parser("keygen", help="print a fresh 256-bit cluster secret")
    s = sub.add_parser("serve", help="run a node"); sec(s)
    s.add_argument("--host", default="0.0.0.0"); s.add_argument("--port", type=int, default=7777)
    s.add_argument("--seed", action="append", default=[], metavar="HOST:PORT")
    s.add_argument("--id"); s.add_argument("--max-peers", type=int, default=32)
    s.add_argument("--workers", type=int, default=0, help="process-pool size for compute jobs (0 = threads)")
    s.add_argument("--no-mesh", action="store_true", help="dial seeds only; do not auto-mesh via PEX")
    s.add_argument("--stats-interval", type=float, default=5.0)
    c = sub.add_parser("submit", help="join as observer, run one job, print results + telemetry"); sec(c)
    c.add_argument("--seed", action="append", required=True, metavar="HOST:PORT")
    c.add_argument("job", choices=["echo", "primes", "hash", "prompt"])
    c.add_argument("--lo", type=int, default=0); c.add_argument("--hi", type=int, default=10_000_000)
    c.add_argument("--iters", type=int, default=1_000_000)
    c.add_argument("--text", default="  Contact: alice@example.com  "); c.add_argument("--stages", default="strip,lower,mask")
    c.add_argument("--wait", type=float, default=10.0); c.add_argument("--timeout", type=float, default=30.0)
    b = sub.add_parser("bench", help="in-process localhost cluster benchmark")
    b.add_argument("--nodes", type=int, default=8); b.add_argument("--events", type=int, default=500)
    b.add_argument("--payload-bytes", type=int, default=256)
    b.add_argument("--topology", choices=["mesh", "line"], default="mesh")
    b.add_argument("--base-port", type=int, default=47000)
    a = ap.parse_args()
    if a.cmd == "keygen":
        print(secrets.token_hex(32)); return
    try:
        asyncio.run({"serve": _serve, "submit": _submit, "bench": _bench}[a.cmd](a))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
