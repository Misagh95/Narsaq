#!/usr/bin/env python3
"""تست پنجره بومی: سرور لوکال در thread، پنجره pywebview باز می‌شود و بعد از 5 ثانیه بسته می‌شود."""
import sys
import threading
import time
from http.server import ThreadingHTTPServer

sys.path.insert(0, ".")
import narsaq_gui as gui

server = ThreadingHTTPServer(("127.0.0.1", 8799), gui.Handler)
url = "http://127.0.0.1:8799"

t = threading.Thread(target=server.serve_forever, daemon=True)
t.start()
print(f"server up at {url}")

import webview


def auto_close(window, seconds):
    time.sleep(seconds)
    window.destroy()
    print("window closed by timer")


w = webview.create_window("Narsaq Test", url, width=1100, height=760)
webview.start(auto_close, (w, 5), private_mode=False)
server.shutdown()
print("DESKTOP TEST PASSED")
