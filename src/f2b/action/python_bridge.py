import json
import logging
import os
import pickle
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
ban_manager = SimpleNamespace(
    size=lambda: stats["banned"],
    getBanTotal=lambda: stats["banned_total"],
)
fail_manager = SimpleNamespace(
    size=lambda: stats["found"],
    getFailTotal=lambda: stats["found_total"],
)
jail = SimpleNamespace(
    name=None,
    database=None,
    actions=SimpleNamespace(getBanTime=lambda: bantime, banManager=ban_manager),
    filter=SimpleNamespace(failManager=fail_manager),
)
action = None
for line in sys.stdin:
    try:
        request = json.loads(line)
        bantime = request["bantime"]
        if request["operation"] == "load":
            jail.name = request["jail"]
            db_filename = request.get("database")
            # shortcut: exposes database.filename only; forward DB queries if a Python action needs them
            jail.database = (
                SimpleNamespace(filename=db_filename)
                if db_filename is not None
                else None
            )
            action = load_action(request)
            value = None
        else:
            value = operate(action, request)
        response = (0, value, capabilities(action))
        payload = pickle.dumps(response, protocol=4)
    except Exception as exc:
        payload = pickle.dumps((1, str(exc), None), protocol=4)
    reply_pipe.write(struct.pack("!I", len(payload)))
    reply_pipe.write(payload)
    reply_pipe.flush()
