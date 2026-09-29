"""Integrações nativas com a API do Windows (Win32 via ``ctypes``, sem dependências).

* **Gerenciador de Credenciais** (``CredWriteW``/``CredReadW``): senhas SSH e
  passphrases guardadas criptografadas pelo Windows (DPAPI) em vez de texto;
* **Visualizador de Eventos** (``ReportEventW``): alertas e ações auditáveis no
  log "Aplicativo";
* **Barra de título** (``DwmSetWindowAttribute``): modo escuro e cor ciano;
* **Barra de tarefas** (``FlashWindowEx``): pisca em alertas críticos;
* **Inicialização** (registro ``HKCU\\...\\Run``): iniciar com o Windows;
* **Energia** (``SetThreadExecutionState``): impede a suspensão durante o monitoramento;
* **ICMP** (``IcmpSendEcho``): latência até o servidor sem privilégios de administrador.

As estruturas usam tipos de tamanho fixo (``c_uint32``/``c_void_p``) para que o
layout seja idêntico ao do Windows x64 e possa ser verificado em testes em
qualquer sistema. Todas as funções são seguras fora do Windows (retornam
``None``/``False``) e nunca propagam erros de API para a interface.
"""

from __future__ import annotations

import ctypes
import logging
import socket
import subprocess
import sys
import time
from ctypes import POINTER, Structure, byref, c_ubyte, c_uint16, c_uint32, c_void_p, c_wchar_p, sizeof
from pathlib import Path

log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"
APP_SOURCE = "FirawynixMonitor"
CREDENTIAL_PREFIX = "FirawynixMonitor/"


def _dll(name: str):
    if not IS_WINDOWS:
        return None
    try:
        return ctypes.WinDLL(name, use_last_error=True)
    except OSError:  # pragma: no cover - DLL ausente (Windows muito antigo)
        log.debug("DLL %s indisponível", name, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Estruturas (layout x64)
# ---------------------------------------------------------------------------

class FILETIME(Structure):
    _fields_ = [("dwLowDateTime", c_uint32), ("dwHighDateTime", c_uint32)]


class CREDENTIALW(Structure):
    _fields_ = [
        ("Flags", c_uint32),
        ("Type", c_uint32),
        ("TargetName", c_wchar_p),
        ("Comment", c_wchar_p),
        ("LastWritten", FILETIME),
        ("CredentialBlobSize", c_uint32),
        ("CredentialBlob", POINTER(c_ubyte)),
        ("Persist", c_uint32),
        ("AttributeCount", c_uint32),
        ("Attributes", c_void_p),
        ("TargetAlias", c_wchar_p),
        ("UserName", c_wchar_p),
    ]


class FLASHWINFO(Structure):
    _fields_ = [("cbSize", c_uint32), ("hwnd", c_void_p), ("dwFlags", c_uint32), ("uCount", c_uint32),
                ("dwTimeout", c_uint32)]


class IP_OPTION_INFORMATION(Structure):
    _fields_ = [("Ttl", c_ubyte), ("Tos", c_ubyte), ("Flags", c_ubyte), ("OptionsSize", c_ubyte),
                ("OptionsData", c_void_p)]


class ICMP_ECHO_REPLY(Structure):
    _fields_ = [("Address", c_uint32), ("Status", c_uint32), ("RoundTripTime", c_uint32),
                ("DataSize", c_uint16), ("Reserved", c_uint16), ("Data", c_void_p),
                ("Options", IP_OPTION_INFORMATION)]


CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2
CRED_MAX_BLOB = 5 * 512
ERROR_NOT_FOUND = 1168
EVENTLOG_ERROR, EVENTLOG_WARNING, EVENTLOG_INFORMATION = 0x0001, 0x0002, 0x0004
FLASHW_ALL, FLASHW_TIMERNOFG = 0x3, 0xC
ES_CONTINUOUS, ES_SYSTEM_REQUIRED = 0x80000000, 0x00000001
DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, DWMWA_USE_IMMERSIVE_DARK_MODE = 19, 20
DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR = 34, 35, 36
IP_SUCCESS = 0

_advapi32 = _dll("advapi32")
_user32 = _dll("user32")
_kernel32 = _dll("kernel32")
_dwmapi = _dll("dwmapi")
_iphlpapi = _dll("iphlpapi")

if _advapi32 is not None:
    _advapi32.CredWriteW.argtypes = (POINTER(CREDENTIALW), c_uint32)
    _advapi32.CredWriteW.restype = ctypes.c_int
    _advapi32.CredReadW.argtypes = (c_wchar_p, c_uint32, c_uint32, POINTER(POINTER(CREDENTIALW)))
    _advapi32.CredReadW.restype = ctypes.c_int
    _advapi32.CredDeleteW.argtypes = (c_wchar_p, c_uint32, c_uint32)
    _advapi32.CredDeleteW.restype = ctypes.c_int
    _advapi32.CredEnumerateW.argtypes = (c_wchar_p, c_uint32, POINTER(c_uint32),
                                         POINTER(POINTER(POINTER(CREDENTIALW))))
    _advapi32.CredEnumerateW.restype = ctypes.c_int
    _advapi32.CredFree.argtypes = (c_void_p,)
    _advapi32.CredFree.restype = None
    _advapi32.RegisterEventSourceW.argtypes = (c_wchar_p, c_wchar_p)
    _advapi32.RegisterEventSourceW.restype = c_void_p
    _advapi32.ReportEventW.argtypes = (c_void_p, c_uint16, c_uint16, c_uint32, c_void_p, c_uint16, c_uint32,
                                       POINTER(c_wchar_p), c_void_p)
    _advapi32.ReportEventW.restype = ctypes.c_int
    _advapi32.DeregisterEventSource.argtypes = (c_void_p,)
    _advapi32.DeregisterEventSource.restype = ctypes.c_int
if _user32 is not None:
    _user32.GetParent.argtypes = (c_void_p,)
    _user32.GetParent.restype = c_void_p
    _user32.FlashWindowEx.argtypes = (POINTER(FLASHWINFO),)
    _user32.FlashWindowEx.restype = ctypes.c_int
    _user32.GetForegroundWindow.argtypes = ()
    _user32.GetForegroundWindow.restype = c_void_p
if _kernel32 is not None:
    _kernel32.SetThreadExecutionState.argtypes = (c_uint32,)
    _kernel32.SetThreadExecutionState.restype = c_uint32
if _dwmapi is not None:
    _dwmapi.DwmSetWindowAttribute.argtypes = (c_void_p, c_uint32, c_void_p, c_uint32)
    _dwmapi.DwmSetWindowAttribute.restype = ctypes.c_long
if _iphlpapi is not None:
    _iphlpapi.IcmpCreateFile.argtypes = ()
    _iphlpapi.IcmpCreateFile.restype = c_void_p
    _iphlpapi.IcmpCloseHandle.argtypes = (c_void_p,)
    _iphlpapi.IcmpCloseHandle.restype = ctypes.c_int
    _iphlpapi.IcmpSendEcho.argtypes = (c_void_p, c_uint32, c_void_p, c_uint16, c_void_p, c_void_p, c_uint32,
                                       c_uint32)
    _iphlpapi.IcmpSendEcho.restype = c_uint32


# ---------------------------------------------------------------------------
# Gerenciador de Credenciais
# ---------------------------------------------------------------------------

class CredentialError(Exception):
    pass


def credential_target(server: str, kind: str = "password") -> str:
    """Nome padrão da credencial genérica (visível em "Gerenciador de Credenciais")."""
    return f"{CREDENTIAL_PREFIX}{server}" if kind == "password" else f"{CREDENTIAL_PREFIX}{server}/{kind}"


def encode_secret(secret: str) -> bytes:
    """UTF-16LE: o mesmo formato gravado pelo ``cmdkey /generic`` e pelo keyring."""
    data = secret.encode("utf-16-le")
    if len(data) > CRED_MAX_BLOB:
        raise CredentialError(f"Segredo longo demais ({len(data)} bytes; máximo {CRED_MAX_BLOB}).")
    return data


def decode_secret(blob: bytes) -> str:
    if len(blob) % 2 == 0:
        try:
            return blob.decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    return blob.decode("utf-8", errors="replace")


def cred_write(target: str, secret: str, username: str = "") -> None:
    if _advapi32 is None:
        raise CredentialError("O Gerenciador de Credenciais só existe no Windows.")
    blob = encode_secret(secret)
    buffer = (c_ubyte * max(1, len(blob))).from_buffer_copy(blob or b"\0")
    credential = CREDENTIALW(
        Type=CRED_TYPE_GENERIC, TargetName=target, Comment="Firawynix Monitor (SSH)",
        CredentialBlobSize=len(blob), CredentialBlob=ctypes.cast(buffer, POINTER(c_ubyte)),
        Persist=CRED_PERSIST_LOCAL_MACHINE, UserName=username or None,
    )
    if not _advapi32.CredWriteW(byref(credential), 0):
        raise CredentialError(f"CredWriteW falhou (erro {ctypes.get_last_error()}).")


def cred_read(target: str) -> str | None:
    if _advapi32 is None:
        return None
    pointer = POINTER(CREDENTIALW)()
    if not _advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, byref(pointer)):
        error = ctypes.get_last_error()
        if error != ERROR_NOT_FOUND:
            log.warning("CredReadW(%s) falhou (erro %s)", target, error)
        return None
    try:
        credential = pointer.contents
        blob = ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize)
        return decode_secret(blob)
    finally:
        _advapi32.CredFree(pointer)


def cred_delete(target: str) -> bool:
    if _advapi32 is None:
        return False
    return bool(_advapi32.CredDeleteW(target, CRED_TYPE_GENERIC, 0))


def cred_list(prefix: str = CREDENTIAL_PREFIX) -> list[tuple[str, str]]:
    """``[(alvo, usuário)]`` das credenciais do app (nunca devolve os segredos)."""
    if _advapi32 is None:
        return []
    count = c_uint32()
    array = POINTER(POINTER(CREDENTIALW))()
    if not _advapi32.CredEnumerateW(prefix + "*", 0, byref(count), byref(array)):
        return []
    try:
        return [(array[i].contents.TargetName or "", array[i].contents.UserName or "") for i in range(count.value)]
    finally:
        _advapi32.CredFree(array)


# ---------------------------------------------------------------------------
# Visualizador de Eventos
# ---------------------------------------------------------------------------

EVENT_IDS = {
    "service_failed": 1001, "service_recovered": 1002, "connection_lost": 1003, "connection_restored": 1004,
    "threshold": 1005, "endpoint": 1006, "security": 1007, "smart": 1008, "action": 1009, "bandwidth": 1010,
    "login": 1011, "app": 1000,
}
_LEVEL_TYPES = {"critical": EVENTLOG_ERROR, "error": EVENTLOG_ERROR, "warning": EVENTLOG_WARNING,
                "info": EVENTLOG_INFORMATION}


class EventLog:
    """Grava no log "Aplicativo". Para mensagens sem o aviso "descrição não encontrada",
    registre a origem uma vez (PowerShell como administrador)::

        New-EventLog -LogName Application -Source FirawynixMonitor
    """

    def __init__(self, source: str = APP_SOURCE) -> None:
        self.source = source
        self._handle = None
        if _advapi32 is not None:
            self._handle = _advapi32.RegisterEventSourceW(None, source)
            if not self._handle:
                log.warning("RegisterEventSourceW falhou (erro %s)", ctypes.get_last_error())

    @property
    def available(self) -> bool:
        return bool(self._handle)

    def write(self, message: str, level: str = "info", category: str = "app") -> bool:
        if not self._handle:
            return False
        strings = (c_wchar_p * 1)(message[:31000])
        ok = _advapi32.ReportEventW(self._handle, _LEVEL_TYPES.get(level, EVENTLOG_INFORMATION), 0,
                                    EVENT_IDS.get(category, 1000), None, 1, 0, strings, None)
        if not ok:
            log.debug("ReportEventW falhou (erro %s)", ctypes.get_last_error())
        return bool(ok)

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle and _advapi32 is not None:
            _advapi32.DeregisterEventSource(handle)


# ---------------------------------------------------------------------------
# Janela: barra de título, piscar na barra de tarefas
# ---------------------------------------------------------------------------

def colorref(hex_color: str) -> int:
    """``#RRGGBB`` → COLORREF (``0x00BBGGRR``)."""
    value = hex_color.lstrip("#")
    red, green, blue = int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)
    return (blue << 16) | (green << 8) | red


def window_handle(widget) -> int | None:
    """HWND da janela de nível superior de um widget Tk (o frame externo do Windows)."""
    if _user32 is None:
        return None
    try:
        return _user32.GetParent(widget.winfo_id()) or None
    except Exception:  # noqa: BLE001
        return None


def style_title_bar(widget, *, dark: bool, caption: str | None = None, border: str | None = None,
                    text: str | None = None) -> bool:
    """Modo escuro + cores da barra de título (cores exigem Windows 11)."""
    hwnd = window_handle(widget)
    if hwnd is None or _dwmapi is None:
        return False
    value = ctypes.c_int(1 if dark else 0)
    for attribute in (DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWA_USE_IMMERSIVE_DARK_MODE_OLD):
        if _dwmapi.DwmSetWindowAttribute(hwnd, attribute, byref(value), sizeof(value)) == 0:
            break
    applied = True
    for attribute, color in ((DWMWA_CAPTION_COLOR, caption), (DWMWA_BORDER_COLOR, border),
                             (DWMWA_TEXT_COLOR, text)):
        if color:
            ref = c_uint32(colorref(color))
            applied &= _dwmapi.DwmSetWindowAttribute(hwnd, attribute, byref(ref), sizeof(ref)) == 0
    return applied


def flash_taskbar(widget, count: int = 5) -> bool:
    """Pisca o botão na barra de tarefas até a janela receber foco."""
    hwnd = window_handle(widget)
    if hwnd is None or _user32 is None or _user32.GetForegroundWindow() == hwnd:
        return False
    info = FLASHWINFO(cbSize=sizeof(FLASHWINFO), hwnd=hwnd, dwFlags=FLASHW_ALL | FLASHW_TIMERNOFG,
                      uCount=count, dwTimeout=0)
    return bool(_user32.FlashWindowEx(byref(info)))


# ---------------------------------------------------------------------------
# Energia
# ---------------------------------------------------------------------------

def prevent_sleep(enabled: bool) -> bool:
    """Deve ser chamado pela thread da UI (o estado vale enquanto ela existir)."""
    if _kernel32 is None:
        return False
    flags = ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if enabled else 0)
    return _kernel32.SetThreadExecutionState(flags) != 0


# ---------------------------------------------------------------------------
# Iniciar com o Windows
# ---------------------------------------------------------------------------

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def autostart_command(config_path: Path | None = None) -> str:
    """Linha de comando registrada em ``Run`` (sempre com ``--minimized``)."""
    if getattr(sys, "frozen", False):
        args = [sys.executable]
    else:
        python = Path(sys.executable)
        pythonw = python.with_name("pythonw.exe")
        args = [str(pythonw if pythonw.exists() else python), str(Path(__file__).resolve().parent.parent / "main.py")]
    args.append("--minimized")
    if config_path is not None:
        args += ["--config", str(Path(config_path).resolve())]
    return subprocess.list2cmdline(args)


def autostart_enabled(name: str = APP_SOURCE) -> bool:
    if not IS_WINDOWS:
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as key:
            winreg.QueryValueEx(key, name)
        return True
    except OSError:
        return False


def set_autostart(enabled: bool, command: str, name: str = APP_SOURCE) -> bool:
    if not IS_WINDOWS:
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, command)
            else:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
        return True
    except OSError:
        log.warning("Falha ao alterar a inicialização automática", exc_info=True)
        return False


# ---------------------------------------------------------------------------
# ICMP (ping) sem privilégios
# ---------------------------------------------------------------------------

def ipv4_to_ipaddr(address: str) -> int:
    """IPv4 em ordem de rede, lido como ULONG little-endian (tipo ``IPAddr``)."""
    return int.from_bytes(socket.inet_aton(address), "little")


def icmp_ping(host: str, timeout_ms: int = 1000) -> float | None:
    """Latência em ms via ``IcmpSendEcho`` (IPv4). None = sem resposta/indisponível."""
    if _iphlpapi is None:
        return None
    try:
        address = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except (OSError, IndexError):
        return None
    handle = _iphlpapi.IcmpCreateFile()
    if not handle or handle == c_void_p(-1).value:
        return None
    try:
        payload = b"firawynix-monitor-ping-0123456789"[:32]
        request = ctypes.create_string_buffer(payload, len(payload))
        reply_size = sizeof(ICMP_ECHO_REPLY) + len(payload) + 8 + 64
        reply = ctypes.create_string_buffer(reply_size)
        started = time.perf_counter()
        count = _iphlpapi.IcmpSendEcho(handle, ipv4_to_ipaddr(address), request, len(payload), None, reply,
                                       reply_size, int(timeout_ms))
        wall = (time.perf_counter() - started) * 1000
        if not count:
            return None
        echo = ICMP_ECHO_REPLY.from_buffer_copy(reply.raw[:sizeof(ICMP_ECHO_REPLY)])
        if echo.Status != IP_SUCCESS:
            return None
        return float(echo.RoundTripTime) if echo.RoundTripTime else round(min(wall, 1.0), 2)
    finally:
        _iphlpapi.IcmpCloseHandle(handle)
