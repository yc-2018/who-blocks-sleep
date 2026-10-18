# -*- coding: utf-8 -*-
"""
谁在阻止休眠 (Who Blocks Sleep)
--------------------------------
一个 Windows 小工具：
  1. 实时列出正在阻止系统进入睡眠 / 关闭显示器的程序（powercfg /requests）
  2. 一键强行结束那个进程（OpenProcess + TerminateProcess，失败回退 taskkill）
  3. 不想杀进程？可以让系统直接忽略它的电源请求（powercfg /requestsoverride）
  4. 附带唤醒诊断：唤醒定时器、上次唤醒来源、可唤醒设备、系统睡眠诊断报告

依赖：仅 Python 标准库（tkinter / ctypes / subprocess）。
注意：读取电源请求和处理都需要管理员权限。
"""

import ctypes
import ctypes.wintypes as wt
import os
import queue
import re
import subprocess
import sys
import threading
import time

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except Exception:  # pragma: no cover
    import tkinter as tk
    from tkinter import ttk, messagebox

APP_TITLE = "谁在阻止休眠"
APP_VER = "1.0"

# ---------------------------------------------------------------- 主题配色
BG = "#F4F6F9"
CARD = "#FFFFFF"
BORDER = "#E2E6ED"
TXT = "#1F2329"
TXT2 = "#6B7280"
ACCENT = "#2F6FED"
DANGER = "#D93B3B"
DANGER_HOVER = "#C22F2F"
WARN = "#E08A00"
OK = "#1FA971"

UI_FONT = "Microsoft YaHei UI"
MONO_FONT = "Consolas"
F_TITLE = 16   # 抬头大字
F_BODY = 11    # 正文 / 表格 / 按钮
F_SMALL = 10   # 辅助说明
F_EMPTY = 13   # 空状态标题

CAT_LABEL = {
    "SYSTEM": "系统睡眠",
    "DISPLAY": "关闭显示器",
    "AWAYMODE": "离开模式",
    "EXECUTION": "无人值守",
    "PERFBOOST": "性能提升",
    "ACTIVELOCKSCREEN": "锁屏保持",
    "UNKNOWN": "未知请求",
}
CAT_ORDER = ["SYSTEM", "DISPLAY", "AWAYMODE", "EXECUTION", "PERFBOOST", "ACTIVELOCKSCREEN", "UNKNOWN"]
CAT_DESC = {
    "SYSTEM": "阻止电脑自动进入睡眠 / 待机",
    "DISPLAY": "阻止屏幕自动关闭",
    "AWAYMODE": "阻止进入离开模式",
    "EXECUTION": "要求保持无人值守运行",
    "PERFBOOST": "请求性能提升模式",
    "ACTIVELOCKSCREEN": "锁屏时保持活动",
}

RE_SECTION = re.compile(r"^\s*([A-Z][A-Z_]{3,}):\s*$")
RE_ENTRY = re.compile(r"^\s*\[(PROCESS|SERVICE|DRIVER)\]\s*(.*?)\s*$")
RE_OVR_CAT = re.compile(r"^\s*\[([A-Z][A-Z_]{3,})\]\s*$")
RE_OVR_ITEM = re.compile(r"^\s*(PROCESS|SERVICE|DRIVER)\s+(.+?)\s*$")
RE_PLAIN = re.compile(r"^[\w\u4e00-\u9fa5][\w \u4e00-\u9fa5\-\.]{0,14}$")

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# ---------------------------------------------------------------- 进程 / 内核封装
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.GetLogicalDrives.restype = wt.DWORD
_k32.QueryDosDeviceW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, wt.DWORD]
_k32.QueryDosDeviceW.restype = wt.DWORD
_k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_k32.OpenProcess.restype = wt.HANDLE
_k32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
_k32.TerminateProcess.restype = wt.BOOL
_k32.CloseHandle.argtypes = [wt.HANDLE]
_k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
_k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
_k32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_wchar_p, ctypes.POINTER(wt.DWORD)]
_k32.QueryFullProcessImageNameW.restype = wt.BOOL

PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


def enable_debug_privilege():
    """尝试启用 SeDebugPrivilege，终止高权限进程时更可靠。"""
    try:
        adv = ctypes.WinDLL("advapi32", use_last_error=True)

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wt.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, SE_PRIVILEGE_ENABLED = 0x20, 0x8, 0x2
        adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
        adv.LookupPrivilegeValueW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(LUID)]
        adv.AdjustTokenPrivileges.argtypes = [wt.HANDLE, wt.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), wt.DWORD, ctypes.c_void_p, ctypes.c_void_p]

        htok = wt.HANDLE()
        if not adv.OpenProcessToken(_k32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(htok)):
            return False
        luid = LUID()
        if not adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            _k32.CloseHandle(htok)
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ok = adv.AdjustTokenPrivileges(htok, False, ctypes.byref(tp), 0, None, None)
        _k32.CloseHandle(htok)
        return bool(ok) and ctypes.get_last_error() == 0
    except Exception:
        return False


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _dos_mappings():
    """盘符 -> 设备路径映射，用于把 \\Device\\HarddiskVolume3\\... 还原成 C:\\..."""
    out = {}
    try:
        mask = _k32.GetLogicalDrives()
    except Exception:
        return out
    for i in range(26):
        if mask & (1 << i):
            letter = chr(ord("A") + i) + ":"
            buf = ctypes.create_unicode_buffer(1024)
            if _k32.QueryDosDeviceW(letter, buf, 1024):
                out[buf.value.upper()] = letter + "\\"
    return out


def resolve_path(raw):
    """把内核设备路径转成普通 Windows 路径。"""
    if not raw:
        return raw
    p = raw.strip().strip('"')
    low = p.lower()
    if low.startswith(r"\??\\"):
        p = p[4:]
    elif low.startswith(r"\??\\") or low.startswith("\\\\?\\"):
        p = p[4:]
    if p[:1] == "\\" and not p.lower().startswith(r"\systemroot") and not os.path.exists(p):
        mapped = _dos_mappings()
        for dev in sorted(mapped, key=len, reverse=True):
            if p.upper().startswith(dev):
                rest = p[len(dev):].lstrip("\\")
                p = mapped[dev] + rest
                break
    if p.lower().startswith(r"\systemroot"):
        p = os.path.expandvars("%SystemRoot%") + p[len(r"\SystemRoot"):]
    return p


def iter_processes():
    """返回 {pid: (exe_name, full_path)}"""
    result = {}
    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE or snap is None:
        return result
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = _k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            pid = int(entry.th32ProcessID)
            name = entry.szExeFile
            path = ""
            h = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if h:
                try:
                    size = wt.DWORD(1024)
                    buf = ctypes.create_unicode_buffer(1024)
                    if _k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                        path = buf.value
                finally:
                    _k32.CloseHandle(h)
            result[pid] = (name, path)
            ok = _k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        _k32.CloseHandle(snap)
    return result


def terminate_pid(pid):
    """强行结束进程。返回 (ok, message)。"""
    if pid <= 0:
        return False, "没有有效的 PID"
    h = _k32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if h:
        try:
            if _k32.TerminateProcess(h, 1):
                return True, "已结束"
            err = ctypes.get_last_error()
            msg = f"TerminateProcess 失败（错误码 {err}）"
        finally:
            _k32.CloseHandle(h)
    else:
        err = ctypes.get_last_error()
        msg = f"无法打开进程（错误码 {err}）"
    # 回退 taskkill
    try:
        p = subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=15,
        )
        if p.returncode == 0:
            return True, "已通过 taskkill 结束"
        tail = decode_bytes(p.stderr or p.stdout).strip().splitlines()
        if tail:
            msg += "；taskkill：" + tail[-1]
    except Exception as e:
        msg += f"；taskkill 异常：{e}"
    return False, msg


def decode_bytes(b):
    if not b:
        return ""
    for enc in ("oem", "mbcs", "utf-8", "gbk"):
        try:
            return b.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return b.decode("latin-1", "replace")


# ---------------------------------------------------------------- powercfg
def run_powercfg(args, timeout=25):
    try:
        p = subprocess.run(
            ["powercfg"] + list(args),
            capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=timeout,
        )
        text = (decode_bytes(p.stdout) + "\n" + decode_bytes(p.stderr)).strip()
        return p.returncode, text
    except subprocess.TimeoutExpired:
        return -1, "powercfg 执行超时"
    except Exception as e:
        return -1, f"powercfg 调用失败：{e}"


def _clean_reason(line):
    s = line.strip()
    for sep in (":", "："):
        if sep in s:
            head, _, tail = s.partition(sep)
            if RE_PLAIN.match(head.strip()):
                return tail.strip() or s
    return s


def parse_requests(text):
    """解析 powercfg /requests 文本。"""
    items = []
    cur = "UNKNOWN"
    last = None
    for line in text.splitlines():
        if not line.strip():
            continue
        m = RE_SECTION.match(line)
        if m and m.group(1) in CAT_LABEL:
            cur = m.group(1)
            last = None
            continue
        m = RE_ENTRY.match(line)
        if m:
            last = {
                "cat": cur,
                "kind": m.group(1).upper(),
                "raw": m.group(2).strip(),
                "path": resolve_path(m.group(2).strip()),
                "reason": "",
                "pid": 0,
                "name": "",
            }
            items.append(last)
            continue
        if last is not None and not last["reason"]:
            # 仅当该行不是明显的段标题/条目时，才当成原因行
            if not re.match(r"^\s*\[", line):
                last["reason"] = _clean_reason(line)
    return items


def collect_requests():
    """返回 (items, raw_text, rc, admin_hint)"""
    rc, out = run_powercfg(["/requests"])
    items = parse_requests(out)
    if items:
        procs = iter_processes()
        by_path = {}
        by_name = {}
        for pid, (name, path) in procs.items():
            if path:
                by_path[path.lower()] = (pid, name, path)
                by_name.setdefault(name.lower(), (pid, name, path))
        for it in items:
            key = (it["path"] or "").lower()
            hit = by_path.get(key)
            if hit is None and key:
                # 路径大小写/长短路径差异时的兜底：按文件名匹配
                hit = by_name.get(os.path.basename(key))
            if hit:
                it["pid"], it["name"], it["path"] = hit
            else:
                it["name"] = os.path.basename(it["path"] or it["raw"]) or it["raw"]
    items.sort(key=lambda x: (CAT_ORDER.index(x["cat"]) if x["cat"] in CAT_ORDER else 99, x["name"].lower()))
    admin_hint = (rc != 0 and "管理员" in out) or "管理员" in out
    return items, out, rc, admin_hint


def collect_overrides():
    """返回 (dict{name: set(cats)}, raw)"""
    rc, out = run_powercfg(["/requestsoverride"])
    data = {}
    cur = None
    for line in out.splitlines():
        if not line.strip():
            continue
        m = RE_OVR_CAT.match(line)
        if m:
            cur = m.group(1)
            continue
        m = RE_OVR_ITEM.match(line)
        if m:
            kind, name = m.group(1), m.group(2).strip()
            key = (kind.upper(), name)
            data.setdefault(key, set()).add(cur or "UNKNOWN")
    return data, out


def add_override(caller_type, name, cats):
    args = ["/requestsoverride", caller_type, name] + sorted(cats)
    return run_powercfg(args)


def remove_override(caller_type, name):
    return run_powercfg(["/requestsoverride", caller_type, name])


# ---------------------------------------------------------------- GUI
def px(v, scale=1.0):
    return max(1, int(round(v * scale)))


class App:
    def __init__(self, root):
        self.root = root
        self.scale = 1.0
        dpi = 96
        try:
            dpi = ctypes.windll.user32.GetDpiForSystem()
        except Exception:
            try:
                dpi = ctypes.windll.gdi32.GetDeviceCaps(ctypes.windll.user32.GetDC(0), 88)
            except Exception:
                dpi = 96
        self.scale = max(1.0, min(3.0, dpi / 96.0))

        self.q = queue.Queue()
        self.busy = False
        self.auto = tk.BooleanVar(value=True)
        self.items = []
        self.prev_keys = set()
        self.last_check = ""
        self.admin = is_admin()
        if self.admin:
            enable_debug_privilege()

        root.title(f"{APP_TITLE}  v{APP_VER}")
        root.configure(bg=BG)
        root.minsize(px(880, self.scale), px(560, self.scale))
        w, h = px(1120, self.scale), px(690, self.scale)
        try:
            root.update_idletasks()
            sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
            wa = _work_area()
            if wa:
                wl, wt_, wr, wb = wa
                w = min(w, wr - wl - px(24, self.scale))
                h = min(h, wb - wt_ - px(24, self.scale))
                x = wl + max(0, (wr - wl - w) // 2)
                y = wt_ + max(0, (wb - wt_ - h) // 2)
            else:
                x, y = max(0, (sw - w) // 2), max(0, (sh - h) // 2)
            root.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            root.geometry(f"{w}x{h}")
        try:
            root.tk.call("tk", "scaling", self.scale * 1.3334)
        except Exception:
            pass

        self._init_style()
        self._build()
        self._pump()
        self.refresh_now()
        self._tick()
        root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------------- 样式
    def _init_style(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except Exception:
            pass
        f = (UI_FONT, F_BODY)
        s.configure(".", background=BG, foreground=TXT, font=f)
        s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
        s.configure("TNotebook.Tab", background="#E8ECF2", foreground=TXT2, padding=(px(20, self.scale), px(9, self.scale)),
                    borderwidth=0, font=f)
        s.map("TNotebook.Tab",
              background=[("selected", CARD), ("active", "#F0F3F8")],
              foreground=[("selected", TXT)],
              expand=[("selected", (0, 0, 0, 0))])
        s.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TXT,
                    rowheight=px(34, self.scale), borderwidth=0, font=f, indent=px(4, self.scale))
        s.configure("Treeview.Heading", background="#EDF0F5", foreground="#4B5563",
                    relief="flat", font=(UI_FONT, F_BODY, "bold"), padding=(px(8, self.scale), px(7, self.scale)))
        s.map("Treeview.Heading", background=[("active", "#E4E8EF")])
        s.map("Treeview", background=[("selected", "#D8E6FF")], foreground=[("selected", TXT)])
        s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        s.configure("Vertical.TScrollbar", background="#D5DAE2", troughcolor=CARD,
                    borderwidth=0, arrowsize=px(12, self.scale))
        s.configure("TCheckbutton", background=CARD, foreground=TXT2, font=f)
        s.map("TCheckbutton", background=[("active", CARD)])

    # ---------------- 布局
    def _build(self):
        self._build_header()
        self._build_notebook()
        self._build_statusbar()

    def _build_header(self):
        head = tk.Frame(self.root, bg=CARD, height=px(92, self.scale))
        head.pack(fill="x")
        head.pack_propagate(False)
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")

        left = tk.Frame(head, bg=CARD)
        left.pack(side="left", padx=px(20, self.scale), pady=px(14, self.scale))
        title_row = tk.Frame(left, bg=CARD)
        title_row.pack(anchor="w")
        self.dot = tk.Canvas(title_row, width=px(12, self.scale), height=px(12, self.scale),
                             bg=CARD, highlightthickness=0, bd=0)
        self.dot.pack(side="left", padx=(0, px(8, self.scale)))
        self._dot_id = self.dot.create_oval(px(2, self.scale), px(2, self.scale),
                                            px(11, self.scale), px(11, self.scale),
                                            fill="#C9CFDA", outline="")
        self.head_title = tk.Label(title_row, text="正在读取电源请求…", bg=CARD, fg=TXT,
                                   font=(UI_FONT, F_TITLE, "bold"))
        self.head_title.pack(side="left")
        self.sub_lbl = tk.Label(left, text=" ", bg=CARD, fg=TXT2, font=(UI_FONT, F_BODY), anchor="w")
        self.sub_lbl.pack(anchor="w", padx=(px(20, self.scale), 0), pady=(px(2, self.scale), 0))

        right = tk.Frame(head, bg=CARD)
        right.pack(side="right", padx=px(20, self.scale), pady=px(14, self.scale))

        self.badge = tk.Label(right, text="管理员" if self.admin else "普通权限",
                              bg="#E8F6EF" if self.admin else "#FDECEC",
                              fg=OK if self.admin else DANGER,
                              font=(UI_FONT, F_SMALL), padx=px(8, self.scale), pady=px(2, self.scale))
        self.badge.pack(side="right", padx=(px(10, self.scale), 0))

        tk.Checkbutton(right, text="自动刷新", variable=self.auto, bg=CARD, fg=TXT2,
                       activebackground=CARD, activeforeground=TXT,
                       selectcolor=CARD, font=(UI_FONT, F_BODY), bd=0,
                       highlightthickness=0, cursor="hand2").pack(side="right", padx=(0, px(12, self.scale)))

        self.btn_refresh = self._button(right, "刷新", self.refresh_now, kind="ghost")
        self.btn_refresh.pack(side="right")

    def _set_dot(self, color):
        try:
            self.dot.itemconfigure(self._dot_id, fill=color)
        except Exception:
            pass

    def _build_notebook(self):
        wrap = tk.Frame(self.root, bg=BG)
        wrap.pack(fill="both", expand=True, padx=px(14, self.scale), pady=(px(10, self.scale), 0))

        self.nb = ttk.Notebook(wrap)
        self.nb.pack(fill="both", expand=True)

        self.tab_block = tk.Frame(self.nb, bg=CARD)
        self.tab_wake = tk.Frame(self.nb, bg=CARD)
        self.tab_ign = tk.Frame(self.nb, bg=CARD)
        self.nb.add(self.tab_block, text="  谁在阻止  ")
        self.nb.add(self.tab_wake, text="  唤醒诊断  ")
        self.nb.add(self.tab_ign, text="  已忽略的程序  ")
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab)

        self._build_tab_block()
        self._build_tab_wake()
        self._build_tab_ign()

    def _build_tab_block(self):
        f = self.tab_block
        tk.Frame(f, bg=BORDER, height=1).pack(fill="x", side="bottom")
        bar = tk.Frame(f, bg=CARD)
        bar.pack(side="bottom", fill="x", padx=px(12, self.scale), pady=px(10, self.scale))

        self.btn_kill = self._button(bar, "结束进程", self.do_kill, kind="danger")
        self.btn_kill.pack(side="left")
        self.btn_ignore = self._button(bar, "忽略它的电源请求", self.do_ignore, kind="ghost")
        self.btn_ignore.pack(side="left", padx=(px(8, self.scale), 0))
        self.btn_reveal = self._button(bar, "打开文件位置", self.do_reveal, kind="ghost")
        self.btn_reveal.pack(side="left", padx=(px(8, self.scale), 0))
        self.kill_hint = tk.Label(bar, text="", bg=CARD, fg=TXT2, font=(UI_FONT, F_SMALL))
        self.kill_hint.pack(side="right")

        if not self.admin:
            warn = tk.Frame(f, bg="#FFF7E6")
            warn.pack(side="top", fill="x")
            tk.Label(warn, text="  当前不是管理员权限，读不到电源请求的进程信息。",
                     bg="#FFF7E6", fg="#8A5A00", font=(UI_FONT, F_BODY),
                     anchor="w").pack(side="left", pady=px(7, self.scale), padx=px(6, self.scale))
            self._button(warn, "以管理员身份重启", self.relaunch_admin, kind="small").pack(
                side="right", padx=px(10, self.scale), pady=px(5, self.scale))

        body = tk.Frame(f, bg=CARD)
        body.pack(fill="both", expand=True, padx=px(12, self.scale), pady=(px(10, self.scale), 0))

        self._dots = {
            "SYSTEM": self._make_dot("#D93B3B"),
            "DISPLAY": self._make_dot("#3B7BD9"),
            "other": self._make_dot("#A8B0BD"),
        }

        cols = ("cat", "name", "pid", "reason", "path")
        self.tree = ttk.Treeview(body, columns=cols, show="tree headings", selectmode="extended")
        self.tree.heading("#0", text="")
        self.tree.column("#0", width=px(32, self.scale), minwidth=px(32, self.scale), stretch=False, anchor="center")
        heads = {"cat": ("阻止了什么", 118), "name": ("请求者", 186), "pid": ("PID", 70),
                 "reason": ("原因", 140), "path": ("完整路径", 554)}
        for c in cols:
            text, width = heads[c]
            self.tree.heading(c, text=text, anchor="e" if c == "pid" else "w")
            self.tree.column(c, width=px(width, self.scale),
                             minwidth=px(48, self.scale),
                             anchor="e" if c == "pid" else "w", stretch=(c in ("reason", "path")))
        self.tree.tag_configure("SYSTEM", font=(UI_FONT, F_BODY, "bold"))
        self.tree.tag_configure("DISPLAY", foreground="#1F4F9E")
        self.tree.tag_configure("other", foreground="#6B7280")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda e: self.do_kill())

        vsb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        self.empty_lbl = tk.Label(body, text="正在检查…", bg=CARD, fg=TXT2,
                                  font=(UI_FONT, F_EMPTY), justify="center")
        self.empty_sub = tk.Label(body, text="", bg=CARD, fg="#9AA1AC", font=(UI_FONT, F_BODY))
        self.empty_lbl.place(relx=0.5, rely=0.42, anchor="center")
        self.empty_sub.place(relx=0.5, rely=0.42, anchor="n", y=px(34, self.scale))

        self._set_actions_enabled(False)

    def _build_tab_wake(self):
        f = self.tab_wake
        bar = tk.Frame(f, bg=CARD)
        bar.pack(fill="x", padx=px(12, self.scale), pady=(px(10, self.scale), px(6, self.scale)))
        self._button(bar, "刷新诊断", self.refresh_wake, kind="ghost").pack(side="left")
        self._button(bar, "生成系统睡眠诊断报告", self.do_sleep_report, kind="ghost").pack(
            side="left", padx=(px(8, self.scale), 0))
        tk.Label(bar, text="唤醒定时器会半夜把电脑叫醒；可唤醒设备会让它睡眠中被误触唤醒。",
                 bg=CARD, fg=TXT2, font=(UI_FONT, F_SMALL)).pack(side="right")

        body = tk.Frame(f, bg=CARD)
        body.pack(fill="both", expand=True, padx=px(12, self.scale), pady=(0, px(12, self.scale)))

        self.wake_text = self._text_block(body, "唤醒定时器 / 上次唤醒 / 可唤醒设备")

    def _build_tab_ign(self):
        f = self.tab_ign
        bar = tk.Frame(f, bg=CARD)
        bar.pack(fill="x", padx=px(12, self.scale), pady=(px(10, self.scale), px(6, self.scale)))
        self._button(bar, "刷新", self.refresh_overrides, kind="ghost").pack(side="left")
        self.btn_unignore = self._button(bar, "撤销所选忽略", self.do_unignore, kind="danger")
        self.btn_unignore.pack(side="left", padx=(px(8, self.scale), 0))
        tk.Label(bar, text="被忽略的程序即使申请阻止睡眠，系统也不会理它，但程序本身照常运行。",
                 bg=CARD, fg=TXT2, font=(UI_FONT, F_SMALL)).pack(side="right")

        body = tk.Frame(f, bg=CARD)
        body.pack(fill="both", expand=True, padx=px(12, self.scale), pady=(0, px(12, self.scale)))
        cols = ("name", "kind", "cats")
        self.ign_tree = ttk.Treeview(body, columns=cols, show="headings", selectmode="extended")
        for c, t, w in (("name", "程序 / 服务 / 驱动", 460), ("kind", "类型", 90), ("cats", "被忽略的请求", 240)):
            self.ign_tree.heading(c, text=t, anchor="w")
            self.ign_tree.column(c, width=px(w, self.scale), minwidth=px(60, self.scale), anchor="w",
                                 stretch=(c == "name"))
        self.ign_tree.grid(row=0, column=0, sticky="nsew")
        vsb = ttk.Scrollbar(body, orient="vertical", command=self.ign_tree.yview)
        self.ign_tree.configure(yscrollcommand=vsb.set)
        vsb.grid(row=0, column=1, sticky="ns")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        self.ign_tree.bind("<<TreeviewSelect>>", self._on_ign_select)
        self._ign_set_enabled(False)

        self.ign_empty = tk.Label(body, text="", bg=CARD, fg=TXT2, font=(UI_FONT, F_BODY))
        self.ign_empty.grid(row=1, column=0, columnspan=2, sticky="w", pady=px(6, self.scale))

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=px(16, self.scale), pady=(0, px(8, self.scale)))
        self.status_lbl = tk.Label(bar, text="", bg=BG, fg=TXT2, font=(UI_FONT, F_SMALL), anchor="w")
        self.status_lbl.pack(side="left")
        self.time_lbl = tk.Label(bar, text="", bg=BG, fg=TXT2, font=(UI_FONT, F_SMALL), anchor="e")
        self.time_lbl.pack(side="right")

    # ---------------- 小部件
    def _text_block(self, parent, title):
        box = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        box.pack(fill="both", expand=True)
        tk.Label(box, text=title, bg="#F7F9FC", fg=TXT2, font=(UI_FONT, F_SMALL, "bold"),
                 anchor="w", padx=px(8, self.scale), pady=px(4, self.scale)).pack(fill="x")
        txt = tk.Text(box, bg=CARD, fg=TXT, relief="flat", bd=0, wrap="word",
                      font=(MONO_FONT, F_BODY), padx=px(10, self.scale), pady=px(8, self.scale),
                      insertbackground=TXT, height=10, spacing1=px(1, self.scale),
                      spacing3=px(2, self.scale))
        txt.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(box, orient="vertical", command=txt.yview)
        sb.pack(side="right", fill="y")
        txt.configure(yscrollcommand=sb.set, state="disabled")
        return txt

    def _make_dot(self, color, d=None):
        d = max(8, d or px(9, self.scale))
        img = tk.PhotoImage(master=self.root, width=d, height=d)
        r = d / 2.0
        for y in range(d):
            dy = y + 0.5 - r
            half = (r * r - dy * dy) ** 0.5
            x1 = int(round(r - half))
            x2 = max(x1 + 1, int(round(r + half)))
            img.put(color, to=(x1, y, x2, y + 1))
        return img

    def _button(self, parent, text, cmd, kind="ghost"):
        styles = {
            "danger": dict(bg=DANGER, fg="#FFFFFF", abg=DANGER_HOVER, afg="#FFFFFF", bd=0),
            "ghost": dict(bg="#F1F3F7", fg=TXT, abg="#E4E8EF", afg=TXT, bd=0),
            "small": dict(bg=ACCENT, fg="#FFFFFF", abg="#255CCB", afg="#FFFFFF", bd=0),
        }[kind]
        b = tk.Button(parent, text=text, command=cmd, relief="flat",
                      font=(UI_FONT, F_BODY), cursor="hand2",
                      padx=px(16 if kind != "small" else 12, self.scale),
                      pady=px(8 if kind != "small" else 4, self.scale),
                      bg=styles["bg"], fg=styles["fg"],
                      activebackground=styles["abg"], activeforeground=styles["afg"],
                      bd=styles["bd"], highlightthickness=0)
        return b

    def _set_actions_enabled(self, on):
        state = "normal" if on else "disabled"
        for b in (self.btn_kill, self.btn_ignore, self.btn_reveal):
            b.configure(state=state, cursor="hand2" if on else "arrow")
            if not on:
                b.configure(bg="#F1F3F7", fg="#B4BAC5")
            else:
                b.configure(bg=DANGER if b is self.btn_kill else "#F1F3F7",
                            fg="#FFFFFF" if b is self.btn_kill else TXT)

    # ---------------- 数据刷新
    def refresh_now(self):
        if self.busy:
            return
        self.busy = True
        threading.Thread(target=self._collect_worker, daemon=True).start()

    def _collect_worker(self):
        try:
            items, raw, rc, admin_hint = collect_requests()
            self.q.put(("requests", (items, raw, rc, admin_hint)))
        except Exception as e:
            self.q.put(("error", f"读取失败：{e}"))

    def _pump(self):
        if getattr(self, "_closing", False):
            return
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "requests":
                    self._apply_requests(*payload)
                elif kind == "error":
                    self.sub_lbl.configure(text=payload, fg=DANGER)
                    self.busy = False
                elif kind == "wake":
                    self._apply_wake(payload)
                elif kind == "overrides":
                    self._apply_overrides(*payload)
                elif kind == "toast":
                    self.kill_hint.configure(text=payload, fg=TXT2)
        except queue.Empty:
            pass
        except Exception:
            pass
        try:
            self.root.after(120, self._pump)
        except Exception:
            pass

    def _apply_requests(self, items, raw, rc, admin_hint):
        self.busy = False
        self.items = items
        self.last_check = time.strftime("%H:%M:%S")
        self.time_lbl.configure(text=f"最后检查 {self.last_check}")

        sel = set(self.tree.selection())
        self.tree.delete(*self.tree.get_children())
        new_keys = set()
        for it in items:
            key = f"{it['cat']}|{it['pid']}|{it['path']}"
            if key in new_keys:
                continue
            new_keys.add(key)
            tag = it["cat"] if it["cat"] in ("SYSTEM", "DISPLAY") else "other"
            pid_txt = str(it["pid"]) if it["pid"] else "—"
            self.tree.insert("", "end", iid=key, tags=(tag,), image=self._dots[tag], values=(
                CAT_LABEL.get(it["cat"], it["cat"]),
                it["name"] or "—",
                pid_txt,
                it["reason"] or "—",
                it["path"] or it["raw"],
            ))
        keep = sel & new_keys
        if keep:
            self.tree.selection_set(tuple(keep))

        system_pids = {it["pid"] for it in items if it["cat"] == "SYSTEM" and it["pid"]}
        display_pids = {it["pid"] for it in items if it["cat"] == "DISPLAY" and it["pid"]}
        names = []
        for it in items:
            if it["cat"] == "SYSTEM" and it["name"] and it["name"] not in names:
                names.append(it["name"])

        if rc != 0 and not items:
            if admin_hint or not self.admin:
                self.head_title.configure(text="需要管理员权限才能读取", fg=TXT)
                self.sub_lbl.configure(text="Windows 只允许管理员查看电源请求的详细信息", fg=WARN)
                self._set_dot(WARN)
                self._show_empty("需要管理员权限", "点右上角「以管理员身份重启」即可看到是谁在捣鬼")
            else:
                self.head_title.configure(text="读取失败", fg=DANGER)
                self.sub_lbl.configure(text="powercfg 执行异常，请尝试以管理员身份运行", fg=DANGER)
                self._set_dot(DANGER)
                self._show_empty("读取失败", "powercfg 返回了错误")
        elif not items:
            self.head_title.configure(text="一切正常，没人阻止休眠", fg=TXT)
            self.sub_lbl.configure(text="电脑可以按电源计划正常进入睡眠", fg=TXT2)
            self._set_dot(OK)
            self._show_empty("✓  当前没有程序阻止系统休眠", "电脑现在可以正常自动睡眠 / 关屏")
        else:
            detail = "、".join(names[:3]) + ("…" if len(names) > 3 else "")
            if system_pids:
                self.head_title.configure(text=f"{len(system_pids)} 个程序正在阻止系统休眠", fg="#C0392B")
                self.sub_lbl.configure(text=detail or "见下方列表", fg=TXT2)
                self._set_dot(DANGER)
            else:
                self.head_title.configure(text=f"{len(display_pids)} 个程序让屏幕不关", fg="#B47400")
                self.sub_lbl.configure(text=detail or "只影响关屏，不影响睡眠", fg=TXT2)
                self._set_dot(WARN)
            self._hide_empty()
        self._on_select()

    def _show_empty(self, title, sub):
        self.empty_lbl.configure(text=title, fg=TXT2)
        self.empty_sub.configure(text=sub)
        self.empty_lbl.place(relx=0.5, rely=0.44, anchor="center")
        self.empty_sub.place(relx=0.5, rely=0.44, anchor="n", y=px(38, self.scale))

    def _hide_empty(self):
        self.empty_lbl.place_forget()
        self.empty_sub.place_forget()

    def _on_select(self, _evt=None):
        has = bool(self.tree.selection())
        self._set_actions_enabled(has)

    def _on_ign_select(self, _evt=None):
        self._ign_set_enabled(bool(self.ign_tree.selection()))

    def _ign_set_enabled(self, on):
        self.btn_unignore.configure(
            state="normal" if on else "disabled",
            cursor="hand2" if on else "arrow",
            bg=DANGER if on else "#F1F3F7",
            fg="#FFFFFF" if on else "#B4BAC5")

    def _selected_items(self):
        out = []
        for iid in self.tree.selection():
            cat, pid, path = (iid.split("|", 2) + ["", "", ""])[:3]
            for it in self.items:
                if it["cat"] == cat and str(it["pid"]) == pid and it["path"] == path:
                    out.append(it)
                    break
        return out

    # ---------------- 动作
    def do_kill(self):
        items = self._selected_items()
        if not items:
            return
        targets = {}
        for it in items:
            if it["pid"]:
                targets.setdefault(it["pid"], it)
        if not targets:
            messagebox.showwarning(APP_TITLE, "选中的请求没有对应到具体进程（可能是驱动或服务），无法结束。\n"
                                              "可以改用「忽略它的电源请求」。", parent=self.root)
            return
        lines = "\n".join(f"  · {it['name']}  (PID {pid})" for pid, it in targets.items())
        if not messagebox.askyesno("确认结束进程",
                                   f"即将强行结束以下进程：\n\n{lines}\n\n"
                                   "未保存的数据会丢失，系统关键进程被杀可能导致异常。确定继续？",
                                   icon="warning", parent=self.root):
            return
        ok_list, fail_list = [], []
        for pid, it in targets.items():
            ok, msg = terminate_pid(pid)
            if ok:
                ok_list.append(it["name"])
            else:
                fail_list.append(f"{it['name']}({pid})：{msg}")
        if fail_list:
            messagebox.showwarning(APP_TITLE, "部分进程未能结束：\n\n" + "\n".join(fail_list), parent=self.root)
        if ok_list:
            self.kill_hint.configure(text="已结束：" + "、".join(ok_list), fg=OK)
        self.root.after(400, self.refresh_now)

    def do_ignore(self):
        items = self._selected_items()
        if not items:
            return
        groups = {}
        for it in items:
            if it["kind"] != "PROCESS" or not it["path"]:
                continue
            groups.setdefault(it["path"], set()).add(it["cat"])
        if not groups:
            messagebox.showwarning(APP_TITLE, "只支持对普通程序设置忽略（驱动/服务请直接结束）。", parent=self.root)
            return
        names = "、".join(os.path.basename(p) for p in groups)
        if not messagebox.askyesno("忽略电源请求",
                                   f"让系统从此忽略以下程序的休眠请求：\n\n  {names}\n\n"
                                   "程序会继续运行，但不再能阻止睡眠。可随时在「已忽略的程序」里撤销。",
                                   parent=self.root):
            return
        errs = []
        for path, cats in groups.items():
            rc, out = add_override("PROCESS", path, cats)
            if rc != 0:
                errs.append(f"{os.path.basename(path)}：{out.splitlines()[-1] if out else rc}")
        if errs:
            messagebox.showwarning(APP_TITLE, "部分设置失败：\n\n" + "\n".join(errs), parent=self.root)
        else:
            self.kill_hint.configure(text="已忽略：" + names, fg=OK)
        self.refresh_overrides()
        self.refresh_now()

    def do_reveal(self):
        items = self._selected_items()
        for it in items:
            p = it["path"]
            if p and os.path.exists(p):
                subprocess.Popen(["explorer", "/select,", os.path.normpath(p)])
                return
        messagebox.showinfo(APP_TITLE, "找不到该程序的文件路径。", parent=self.root)

    def do_unignore(self):
        sel = self.ign_tree.selection()
        if not sel:
            return
        targets = [(self.ign_tree.item(i, "values")[1], self.ign_tree.item(i, "values")[0]) for i in sel]
        if not messagebox.askyesno("撤销忽略", f"确定撤销 {len(targets)} 项忽略设置？", parent=self.root):
            return
        errs = []
        for kind, name in targets:
            rc, out = remove_override(kind, name)
            if rc != 0:
                errs.append(f"{name}：{out.splitlines()[-1] if out else rc}")
        if errs:
            messagebox.showwarning(APP_TITLE, "部分撤销失败：\n\n" + "\n".join(errs), parent=self.root)
        self.refresh_overrides()

    def relaunch_admin(self):
        try:
            if getattr(sys, "frozen", False):
                exe, params = sys.executable, ""
            else:
                exe = sys.executable
                params = f'"{os.path.abspath(__file__)}"'
            ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            self.root.destroy()
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"提权失败：{e}", parent=self.root)

    # ---------------- 唤醒诊断
    def refresh_wake(self):
        self._text_set(self.wake_text, "正在读取诊断信息…")
        threading.Thread(target=self._wake_worker, daemon=True).start()

    def _wake_worker(self):
        chunks = []
        for title, args in (("唤醒定时器（powercfg /waketimers）", ["/waketimers"]),
                            ("上次唤醒来源（powercfg /lastwake）", ["/lastwake"]),
                            ("可唤醒本机的设备（powercfg /devicequery wake_armed）", ["/devicequery", "wake_armed"]),
                            ("支持的睡眠状态（powercfg /availablesleepstates）", ["/availablesleepstates"])):
            rc, out = run_powercfg(args)
            body = out.strip() if out.strip() else "（无输出）"
            chunks.append(f"▌ {title}\n{body}\n")
        self.q.put(("wake", "\n".join(chunks)))

    def _apply_wake(self, text):
        self._text_set(self.wake_text, text)

    def do_sleep_report(self):
        rc, out = run_powercfg(["/systemsleepdiagnostics"], timeout=90)
        if rc != 0:
            messagebox.showwarning(APP_TITLE,
                                   "生成诊断报告失败（需要 Windows 10 1903 及以上、且为管理员）。\n\n" + out,
                                   parent=self.root)
        else:
            self.kill_hint.configure(text="诊断报告已生成并在浏览器中打开", fg=OK)

    def _text_set(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    # ---------------- 忽略列表
    def refresh_overrides(self):
        threading.Thread(target=self._ovr_worker, daemon=True).start()

    def _ovr_worker(self):
        try:
            data, raw = collect_overrides()
            self.q.put(("overrides", (data, raw)))
        except Exception as e:
            self.q.put(("overrides", ({}, f"读取失败：{e}")))

    def _apply_overrides(self, data, raw):
        self.ign_tree.delete(*self.ign_tree.get_children())
        self._ign_set_enabled(False)
        if not data:
            self.ign_empty.configure(text="还没有任何忽略设置。", fg=TXT2)
            return
        self.ign_empty.configure(text="")
        for (kind, name), cats in sorted(data.items(), key=lambda kv: kv[0][1].lower()):
            cat_txt = "、".join(CAT_LABEL.get(c, c) for c in
                               sorted(cats, key=lambda c: CAT_ORDER.index(c) if c in CAT_ORDER else 99))
            self.ign_tree.insert("", "end", values=(name, kind, cat_txt))

    # ---------------- 定时
    def _tick(self):
        if getattr(self, "_closing", False):
            return
        try:
            idx = self.nb.index(self.nb.select())
        except Exception:
            idx = 0
        if self.auto.get() and idx == 0 and not self.busy:
            self.refresh_now()
        try:
            self.root.after(3000, self._tick)
        except Exception:
            pass

    def _on_tab(self, _evt):
        try:
            idx = self.nb.index(self.nb.select())
        except Exception:
            return
        if idx == 1 and hasattr(self, "wake_text"):
            if not self.wake_text.get("1.0", "end").strip():
                self.refresh_wake()
        elif idx == 2 and hasattr(self, "ign_tree"):
            self.refresh_overrides()

    def on_close(self):
        self._closing = True
        try:
            self.root.destroy()
        except Exception:
            pass


def resource_path(rel):
    """兼容 PyInstaller onefile 的资源路径。"""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, rel)
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


def _set_dpi_aware():
    """必须在创建任何窗口之前调用，否则 Windows 会把界面位图拉伸，文字发虚。"""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # PROCESS_SYSTEM_DPI_AWARE
        return
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def _work_area():
    """桌面工作区（排除任务栏），返回 (left, top, right, bottom) 或 None。"""
    try:
        class RECT(ctypes.Structure):
            _fields_ = [("left", wt.LONG), ("top", wt.LONG),
                        ("right", wt.LONG), ("bottom", wt.LONG)]

        r = RECT()
        SPI_GETWORKAREA = 0x0030
        if ctypes.windll.user32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(r), 0):
            return r.left, r.top, r.right, r.bottom
    except Exception:
        pass
    return None


def main():
    _set_dpi_aware()
    root = tk.Tk()
    ico = resource_path(os.path.join("assets", "app.ico"))
    if os.path.exists(ico):
        try:
            root.iconbitmap(default=ico)
        except Exception:
            pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
