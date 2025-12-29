#  REGEX IOC & KEYWORDS FOR IOC's
import re


IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b"
)


URL_REGEX = re.compile(
    r"https?://[^\s'\"<>]+"
)


EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"
)


REGKEY_REGEX = re.compile(
    r"\bHKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\s\"']+",
    re.IGNORECASE,
)


SUSPICIOUS_KEYWORDS = [
    "cmd.exe", "powershell", "wscript.exe", "cscript.exe",
    "regsvr32.exe", "schtasks.exe", "Startup", "RunOnce",
    "RunServices", ".onion", "VirtualAlloc", "WinExec",
    "CreateProcess", "LoadLibrary", "GetProcAddress"
]