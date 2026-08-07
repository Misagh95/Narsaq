#!/usr/bin/env python3
"""
build_release.py — ساخت ریلیز دسکتاپ Narsaq
=============================================

ساخت exe مستقل با PyInstaller + پکیج پرتابل (zip شامل exe، لانچر، README و xray)
و فایل SHA256 برای چک‌سام.

استفاده:
    python build_release.py                # ساخت کامل (exe + zip + checksums)
    python build_release.py --skip-build   # فقط پکیج‌بندی (اگر exe از قبل ساخته شده)

خروجی‌ها در پوشه releases/:
    NarsaqDesktop-<ver>.exe
    Narsaq-Desktop-<ver>-portable.zip
    NarsaqDesktop-Setup-<ver>.exe   (نصب‌کننده ویندوز — اگر Inno Setup موجود باشد)
    SHA256SUMS.txt
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
RELEASES_DIR = os.path.join(ROOT, "releases")
BUILD_DIR = os.path.join(ROOT, "build")
DIST_DIR = os.path.join(ROOT, "dist")


def version():
    sys.path.insert(0, ROOT)
    import cf_config_builder as cfb
    return cfb.VERSION


def exe_filename(ver):
    return f"NarsaqDesktop-v{ver}.exe"


def zip_filename(ver):
    return f"Narsaq-Desktop-v{ver}-portable.zip"


def sha256_of(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            data = fh.read(chunk)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


def ensure_xray():
    """مطمئن شو xray.exe کنار اسکریپت هست (برای تست واقعی پراکسی)."""
    exe = os.path.join(ROOT, "bin", "xray.exe")
    if os.path.isfile(exe):
        return exe
    sys.path.insert(0, ROOT)
    import cf_config_builder as cfb
    print("[build] xray.exe پیدا نشد — دانلود خودکار...")
    cfb.download_xray_core(os.path.join(ROOT, "bin"))
    if not os.path.isfile(exe):
        raise RuntimeError("دانلود xray.exe ناموفق بود")
    return exe


def run_pyinstaller(ver):
    print(f"[build] PyInstaller — ساخت {exe_filename(ver)} ...")
    ensure_icon()
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--onefile", "--console",
        "--name", exe_filename(ver).replace(".exe", ""),
        os.path.join(ROOT, "narsaq_gui.py"),
    ]
    ico = os.path.join(ROOT, "assets", "narsaq.ico")
    if os.path.isfile(ico):
        args += ["--icon", ico]
    subprocess.check_call(args, cwd=ROOT)
    exe = os.path.join(DIST_DIR, exe_filename(ver))
    if not os.path.isfile(exe):
        raise RuntimeError(f"خروجی PyInstaller پیدا نشد: {exe}")
    print(f"[build] exe ساخته شد: {exe} ({os.path.getsize(exe) / 1e6:.1f} MB)")
    return exe


def portable_launcher(ver):
    """لانچر bat مخصوص نسخه exe (روی exe باز می‌شود نه روی پایتون)."""
    return (
        "@echo off\r\n"
        "rem Narsaq Desktop launcher (portable)\r\n"
        "cd /d \"%~dp0\"\r\n"
        "echo Starting Narsaq Desktop at http://127.0.0.1:8787 ...\r\n"
        "echo (the browser will open automatically; press Ctrl+C to stop)\r\n"
        f"\"NarsaqDesktop-v{ver}.exe\"\r\n"
        "if errorlevel 1 (\r\n"
        "  echo.\r\n"
        "  echo Failed to start NarsaqDesktop.\r\n"
        "  pause\r\n"
        ")\r\n"
    )


def make_portable_zip(ver, exe_path):
    xray = ensure_xray()
    stage = os.path.join(BUILD_DIR, "portable")
    if os.path.isdir(stage):
        shutil.rmtree(stage)
    os.makedirs(os.path.join(stage, "bin"), exist_ok=True)

    shutil.copy2(exe_path, os.path.join(stage, exe_filename(ver)))
    shutil.copy2(os.path.join(ROOT, "README.md"), os.path.join(stage, "README.md"))
    with open(os.path.join(stage, "start_gui.bat"), "w", encoding="utf-8", newline="") as fh:
        fh.write(portable_launcher(ver))
    shutil.copy2(xray, os.path.join(stage, "bin", "xray.exe"))

    os.makedirs(RELEASES_DIR, exist_ok=True)
    zip_path = os.path.join(RELEASES_DIR, zip_filename(ver))
    if os.path.exists(zip_path):
        os.remove(zip_path)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(stage):
            for name in files:
                full = os.path.join(root, name)
                arc = os.path.relpath(full, stage)
                zf.write(full, arc)
    print(f"[build] zip پرتابل ساخته شد: {zip_path} ({os.path.getsize(zip_path) / 1e6:.1f} MB)")
    return zip_path


def setup_filename(ver):
    return f"NarsaqDesktop-Setup-{ver}.exe"


def find_iscc():
    """پیدا کردن ISCC.exe — در tools/isrc/app (دانلود شده) یا مسیرهای رایج."""
    cands = [
        os.path.join(ROOT, "tools", "isrc", "app", "ISCC.exe"),
        os.path.join(ROOT, "tools", "innosetup", "ISCC.exe"),
        os.environ.get("ISCC", ""),
        r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        r"C:\Program Files\Inno Setup 6\ISCC.exe",
    ]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    import shutil
    return shutil.which("ISCC") or None


def ensure_icon():
    """ساخت آیکن با Pillow اگر نبود (و Pillow موجود بود)."""
    ico = os.path.join(ROOT, "assets", "narsaq.ico")
    if os.path.isfile(ico):
        return ico
    try:
        import make_icon  # tools/make_icon.py
    except Exception:
        pass
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.join(ROOT, "tools"))
        import make_icon
        make_icon.main()
    except Exception as e:
        print(f"[build] آیکن ساخته نشد ({e}) — نصب‌کننده بدون آیکن ساخته می‌شود")
    return ico if os.path.isfile(ico) else None


def make_installer(ver):
    """ساخت نصب‌کننده ویندوز با Inno Setup (اگر ISCC موجود باشد)."""
    iscc = find_iscc()
    if not iscc:
        print("[build] ISCC.exe پیدا نشد — نصب‌کننده ساخته نشد.")
        print("        برای ساخت نصب‌کننده: pip install pillow و اجرای ISCC از Inno Setup 6")
        return None
    ensure_icon()
    if not os.path.isfile(os.path.join(ROOT, "dist", exe_filename(ver))):
        print("[build] dist\\%s نیست — اول exe را بساز" % exe_filename(ver))
        return None
    # مطمئن شو xray.exe هست (نصب‌کننده آن را باندل می‌کند)
    ensure_xray()

    iss = os.path.join(ROOT, "installer.iss")
    if not os.path.isfile(iss):
        print("[build] installer.iss پیدا نشد — نصب‌کننده ساخته نشد")
        return None
    print(f"[build] Inno Setup — ساخت {setup_filename(ver)} ...")
    env = dict(os.environ)
    env["MyAppVer"] = ver
    subprocess.check_call([iscc, iss], cwd=ROOT, env=env)
    out = os.path.join(RELEASES_DIR, setup_filename(ver))
    if not os.path.isfile(out):
        raise RuntimeError(f"نصب‌کننده ساخته نشد: {out}")
    print(f"[build] نصب‌کننده ساخته شد: {out} ({os.path.getsize(out) / 1e6:.1f} MB)")
    return out


def write_checksums(*files):
    lines = []
    for f in files:
        if os.path.isfile(f):
            lines.append(f"{sha256_of(f)}  {os.path.basename(f)}")
    out = os.path.join(RELEASES_DIR, "SHA256SUMS.txt")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"[build] checksums نوشته شد: {out}")
    return out


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="Narsaq Desktop release builder")
    ap.add_argument("--skip-build", action="store_true",
                    help="PyInstaller را اجرا نکن — فقط پکیج کن")
    args = ap.parse_args()

    ver = version()
    print(f"[build] نسخه: {ver}")

    if args.skip_build:
        exe_path = os.path.join(DIST_DIR, exe_filename(ver))
        if not os.path.isfile(exe_path):
            print(f"[build] خطا: {exe_path} وجود ندارد — اول بدون --skip-build اجرا کن")
            return 1
    else:
        exe_path = run_pyinstaller(ver)

    os.makedirs(RELEASES_DIR, exist_ok=True)
    final_exe = os.path.join(RELEASES_DIR, exe_filename(ver))
    try:
        shutil.copy2(exe_path, final_exe)
    except PermissionError:
        print(f"[build] خطا: {final_exe} قفل است (در حال اجراست).")
        print("        ابتدا همه پنجره‌های NarsaqDesktop را ببندید و دوباره اجرا کنید.")
        return 1

    zip_path = make_portable_zip(ver, exe_path)
    setup_path = make_installer(ver)

    checksum_files = [final_exe, zip_path]
    if setup_path:
        checksum_files.append(setup_path)
    write_checksums(*checksum_files)

    print("=" * 56)
    print("  ریلیز آماده شد — پوشه releases/")
    print("=" * 56)
    for f in sorted(os.listdir(RELEASES_DIR)):
        full = os.path.join(RELEASES_DIR, f)
        if os.path.isfile(full):
            print(f"  {f}  ({os.path.getsize(full) / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
