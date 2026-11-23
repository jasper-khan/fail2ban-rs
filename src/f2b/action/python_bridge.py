import json
import logging
import os
import pickle
import sqlite3
import struct
import sys
from types import SimpleNamespace


# Keep action output away from the pipe that carries replies.
reply_pipe = os.fdopen(os.dup(1), "wb")
os.dup2(2, 1)
sys.stdout = sys.stderr
if sys.argv[1]:
    sys.path.insert(0, sys.argv[1])
logging.basicConfig(level=1, format="%(levelno)d %(name)s %(message)s")


def send_frame(value):
    payload = pickle.dumps(value, protocol=4)
    reply_pipe.write(struct.pack("!I", len(payload)))
    reply_pipe.write(payload)
    reply_pipe.flush()


class _RpcCursor:
    arraysize = 1

    def __init__(self):
        self._rows = []
        self._pos = 0
        self.rowcount = -1

    def execute(self, sql, parameters=()):
        from fail2ban.server.database import _json_dumps_safe, _json_loads_safe

        adapted = [
            _json_dumps_safe(v) if isinstance(v, dict) else v for v in parameters
        ]
        send_frame((2, sql, adapted))
        line = sys.stdin.readline()
        if not line:
            raise sqlite3.OperationalError("database bridge closed")
        reply = json.loads(line)
        if not reply["ok"]:
            raise sqlite3.OperationalError(reply["error"])
        json_cols = reply["json_cols"]
        rows = []
        for raw_row in reply["rows"]:
            row = []
            for idx, val in enumerate(raw_row):
                if idx < len(json_cols) and json_cols[idx] and isinstance(val, str):
                    val = _json_loads_safe(val.encode("utf-8", "replace"))
                elif isinstance(val, dict) and "__bytes__" in val:
                    val = bytes(val["__bytes__"])
                row.append(val)
            rows.append(tuple(row))
        self._rows = rows
        self._pos = 0
        self.rowcount = reply["rowcount"]
        return self

    def __iter__(self):
        while self._pos < len(self._rows):
            row = self._rows[self._pos]
            self._pos += 1
            yield row

    def fetchone(self):
        if self._pos >= len(self._rows):
            return None
        row = self._rows[self._pos]
        self._pos += 1
        return row

    def fetchmany(self, size=None):
        n = self.arraysize if size is None else size
        end = self._pos + n
        rows = self._rows[self._pos : end]
        self._pos = min(end, len(self._rows))
        return rows

    def fetchall(self):
        rows = self._rows[self._pos :]
        self._pos = len(self._rows)
        return rows

    def close(self):
        self._rows = []
        self._pos = 0


class _RpcConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        return _RpcCursor()

    def commit(self):
        pass

    def close(self):
        pass


def open_database(info):
    if info is None:
        return None
    from fail2ban.server.database import Fail2BanDb

    class _BridgeFail2BanDb(Fail2BanDb):
        def _connectDB(self, checkIntegrity=False):
            self._bansMergedCache = {}
            if self._dbFilename == ":memory:":
                self._db = _RpcConnection()
                return
            self._db = sqlite3.connect(
                self._dbFilename,
                timeout=5.0,
                check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            self._db.execute("PRAGMA foreign_keys = ON")

        def getBansMerged(self, *args, **kwargs):
            # Rust persists bans outside this process, so avoid stale cached merges.
            self._bansMergedCache.clear()
            return super().getBansMerged(*args, **kwargs)

    db = _BridgeFail2BanDb(info["filename"], purgeAge=info["purgeage"])
    db.maxMatches = info["maxmatches"]
    return db


def load_action(request):
    from fail2ban.server.actions import Actions

    return Actions._load_python_module(request["path"]).Action(
        jail, request["name"], **request["options"]
    )


def action_info(values):
    from fail2ban.server.actions import Actions
    from fail2ban.server.ipdns import IPAddr
    from fail2ban.server.ticket import BanTicket

    fid = IPAddr(
        values["fid"],
        IPAddr.CIDR_RAW if values["raw_fid"] else IPAddr.CIDR_UNSPEC,
    )
    data = values["data"]
    if values["ip"] is not None:
        data["ip"] = IPAddr(values["ip"])
    ticket = BanTicket(fid, values["time"], values["matches"], data)
    ticket.setAttempt(values["attempts"])
    ticket.setBanTime(values["bantime"])
    ticket.setBanCount(values["bancount"], always=True)
    ticket.restored = values["restored"]
    stats.update(values["jail_stats"])
    tags = dict(Actions.ActionInfo.AI_DICT)
    tags.update(
        {
            name: values[name]
            for name in ("ipmatches", "ipjailmatches", "ipfailures", "ipjailfailures")
        }
    )
    return Actions.ActionInfo(ticket, jail, data=tags)


def describe(action, want_methods):
    return [
        key
        for key in dir(action)
        if not key.startswith("_") and callable(getattr(action, key)) == want_methods
    ]


def operate(action, request):
    operation = request["operation"]
    if operation == "consistency_check":
        if request.get("for_flush"):
            stop = bool(request.get("stop"))

            def _beforeRepair():
                if stop and not getattr(action, "actionrepair_on_unban", None):
                    logging.getLogger("fail2ban.actions").error(
                        "Invariant check failed. Flush is impossible."
                    )
                    return False
                return True

            return action.consistencyCheck(_beforeRepair)
        return action.consistencyCheck()
    if operation == "method":
        method = getattr(action, request["key"])
        if "ticket" in request:
            return method(action_info(request["ticket"]))
        return method(**request.get("options", {}))
    if operation == "set":
        key = request["key"]
        method = getattr(action, key, None)
        if callable(method):
            return method(**json.loads(request["value"]) if "value" in request else {})
        setattr(action, key, request["value"])
        return getattr(action, key)
    if operation == "get":
        return getattr(action, request["key"])
    return describe(action, operation == "methods")


def capabilities(action):
    from fail2ban.server.action import CommandAction

    flushable = callable(getattr(action, "flush", None)) and (
        not isinstance(action, CommandAction) or bool(getattr(action, "actionflush", ""))
    )
    return [
        bool(getattr(action, "norestored", False)),
        bool(getattr(action, "_prolongable", False)),
        flushable,
        callable(getattr(action, "reload", None)),
        callable(getattr(action, "clearAllParams", None)),
        callable(getattr(action, "consistencyCheck", None)),
    ]


stats = dict(banned=0, banned_total=0, found=0, found_total=0)
bantime = 0
max_bantime = 0
last_db_purgeage = None
last_db_maxmatches = None
ban_manager = SimpleNamespace(
    size=lambda: stats["banned"],
    getBanTotal=lambda: stats["banned_total"],
)
fail_manager = SimpleNamespace(
    size=lambda: stats["found"],
    getFailTotal=lambda: stats["found_total"],
)
class _JailProxy:
    def __init__(self, actions, filt):
        self.name = None
        self.database = None
        self.actions = actions
        self.filter = filt

    def getMaxBanTime(self):
        return max_bantime

    def __repr__(self):
        return f"Jail({self.name!r})"


jail = _JailProxy(
    SimpleNamespace(getBanTime=lambda: bantime, banManager=ban_manager),
    SimpleNamespace(failManager=fail_manager),
)
action = None
try:
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        try:
            request = json.loads(line)
            bantime = request["bantime"]
            max_bantime = request["max_bantime"]
            if request["operation"] == "load":
                jail.name = request["jail"]
                db_info = request.get("database")
                jail.database = open_database(db_info)
                if db_info is not None:
                    last_db_purgeage = db_info["purgeage"]
                    last_db_maxmatches = db_info["maxmatches"]
                action = load_action(request)
                value = None
            else:
                if jail.database is not None:
                    purge_age = request.get("db_purge_age")
                    if purge_age is not None and purge_age != last_db_purgeage:
                        last_db_purgeage = purge_age
                        jail.database._purgeAge = purge_age
                    max_matches = request.get("db_max_matches")
                    if max_matches is not None and max_matches != last_db_maxmatches:
                        last_db_maxmatches = max_matches
                        jail.database.maxMatches = max_matches
                value = operate(action, request)
            send_frame((0, value, capabilities(action)))
        except Exception as exc:
            send_frame((1, str(exc), None))
finally:
    if jail.database is not None:
        try:
            jail.database.close()
        except Exception:
            pass
