#!/usr/bin/env python3
# Inspect / edit the Vector (LSPosed-fork) modules_config.db scope table.
import sqlite3, sys

DB = r"C:\work\git_code\stealth-poc\kpm\mc.db"

def show():
    d = sqlite3.connect(DB); c = d.cursor()
    print("TABLES:", [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")])
    print("MODULES:")
    for r in c.execute("SELECT mid,module_pkg_name,enabled FROM modules"):
        print("  ", r)
    print("SCOPE:")
    for r in c.execute("SELECT mid,app_pkg_name,user_id FROM scope"):
        print("  ", r)
    d.close()

def add(app, user=0):
    # add `app` to every module's scope that currently scopes com.android.hookdemo
    d = sqlite3.connect(DB); c = d.cursor()
    mids = [r[0] for r in c.execute("SELECT DISTINCT mid FROM scope WHERE app_pkg_name=?", ("com.android.hookdemo",))]
    print("mids scoping hookdemo:", mids)
    for mid in mids:
        c.execute("INSERT OR IGNORE INTO scope (mid, app_pkg_name, user_id) VALUES (?,?,?)", (mid, app, user))
        print(f"  + scope mid={mid} app={app} user={user}")
    d.commit(); d.close()

if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "add":
        add(sys.argv[2])
    show()
