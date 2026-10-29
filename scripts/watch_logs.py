"""Read-only live log viewer for a miner running without a console."""

import argparse
import os
import re
import sys
import time
from pathlib import Path

RECORD = re.compile(
    r"^(\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) - (\w+) - .*? - \[[^]]+\]: (.*)$"
)


def open_log(path):
    if os.name != "nt":
        return path.open("rb")

    # Permit Windows log rotation even while a read is in progress.
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(str(path), 0x80000000, 0x7, None, 3, 0x80, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except OSError:
        kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel.CloseHandle(handle)
        raise
    return os.fdopen(descriptor, "rb")


class LogFollower:
    def __init__(self, path, *, debug=False, tail=40):
        self.path = Path(path)
        self.debug = debug
        self.tail = tail
        self.identity = None
        self.offset = 0
        self.partial = b""
        self.visible = False

    def read(self):
        initial = self.identity is None
        with open_log(self.path) as source:
            stat = os.fstat(source.fileno())
            identity = (stat.st_dev, stat.st_ino)
            if identity != self.identity or stat.st_size < self.offset:
                self.offset = max(0, stat.st_size - 256 * 1024) if initial else 0
                self.partial = b""
                self.visible = False
            source.seek(self.offset)
            chunk = source.read()
            if initial and self.offset:
                chunk = chunk.partition(b"\n")[2]
            self.offset = source.tell()
            self.identity = identity

        lines = (self.partial + chunk).split(b"\n")
        self.partial = lines.pop()
        output = []
        for raw in lines:
            line = raw.decode("utf-8", errors="replace").rstrip("\r")
            record = RECORD.match(line)
            if record:
                date, level, message = record.groups()
                self.visible = self.debug or level in {"INFO", "WARNING", "ERROR", "CRITICAL"}
                if self.visible:
                    output.append(f"{date} [{level}] {message}")
            elif self.visible:
                output.append(line)
        return output[-self.tail:] if initial else output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log_file", type=Path)
    parser.add_argument("--debug", action="store_true", help="Also show DEBUG records")
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if os.name == "nt":
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW("Twitch Channel Points Miner - Live log")

    path = args.log_file.resolve()
    print("Twitch Channel Points Miner - Live log", flush=True)
    print(f"Source: {path}", flush=True)
    print("Showing " + ("all log levels." if args.debug else "INFO, WARNING, ERROR and CRITICAL."), flush=True)
    print("Close this window or press Ctrl+C to exit the viewer. The miner keeps running.\n", flush=True)
    follower = LogFollower(path, debug=args.debug)
    previous_error = None
    try:
        while True:
            try:
                for line in follower.read():
                    print(line, flush=True)
                previous_error = None
            except OSError as error:
                kind = type(error).__name__
                if kind != previous_error:
                    print(f"Waiting for the log file ({kind})...", flush=True)
                previous_error = kind
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
