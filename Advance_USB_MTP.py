import os
import subprocess
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog

# ================= CONFIG =================
MTP_KEYWORDS = ["mtp", "android", "portable", "samsung", "xiaomi", "poco", "apple", "google", "vivo", "oppo", "oneplus",
                "motorola", "realme", "iqoo", "nothing", "honor", "tecno", "infinix", "asus", "sony", "huawei", "hmd",
                "lava"]

SYSTEM_DIRS = [
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "Documents"),
]


# ================= MAIN APP =================
class AdvancedEndpointMonitor:

    def __init__(self, root):
        self.root = root
        self.root.title("Advanced USB & Mobile Endpoint Monitoring Framework")
        self.root.geometry("1350x750")

        self.monitoring = True
        self.report_dir = None  # To store the chosen directory

        self.prev_drives = set()
        self.prev_mtp = set()

        self.allowlist = set()
        self.blocklist = set()

        # === SNAPSHOTS (from usb10.py) ===
        self.usb_snapshots = {}
        self.system_snapshot = self.snapshot_system()

        self.build_ui()

        threading.Thread(target=self.usb_loop, daemon=True).start()
        threading.Thread(target=self.mtp_loop, daemon=True).start()
        threading.Thread(target=self.file_activity_loop, daemon=True).start()

    # ================= UI =================
    def build_ui(self):
        ttk.Label(
            self.root,
            text="Advanced External Device Monitoring Framework",
            font=("Segoe UI", 18, "bold")
        ).pack(pady=10)

        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True)

        self.tab_usb = ttk.Frame(self.tabs)
        self.tab_mtp = ttk.Frame(self.tabs)
        self.tab_files = ttk.Frame(self.tabs)
        self.tab_logs = ttk.Frame(self.tabs)
        self.tab_help = ttk.Frame(self.tabs)  # Added Help Tab

        self.tabs.add(self.tab_usb, text="USB Devices")
        self.tabs.add(self.tab_mtp, text="Mobile (MTP)")
        self.tabs.add(self.tab_files, text="File Activity")
        self.tabs.add(self.tab_logs, text="Logs")
        self.tabs.add(self.tab_help, text="Help")  # Added to Notebook

        self.build_usb_tab()
        self.build_mtp_tab()
        self.build_file_tab()
        self.build_logs_tab()
        self.build_help_tab()  # Call to build Help UI

    def build_usb_tab(self):
        cols = ("Drive", "VID/PID", "Serial", "Status", "Time")
        self.usb_table = ttk.Treeview(self.tab_usb, columns=cols, show="headings")
        for c in cols:
            self.usb_table.heading(c, text=c)
            self.usb_table.column(c, width=240)
        self.usb_table.pack(fill="both", expand=True)

    def build_mtp_tab(self):
        self.mtp_box = tk.Listbox(self.tab_mtp, font=("Consolas", 11))
        self.mtp_box.pack(fill="both", expand=True)

    def build_file_tab(self):
        cols = ("Event", "File", "Location", "Time")
        self.file_table = ttk.Treeview(self.tab_files, columns=cols, show="headings")
        for c in cols:
            self.file_table.heading(c, text=c)
            self.file_table.column(c, width=300)
        self.file_table.pack(fill="both", expand=True)

    def build_logs_tab(self):
        # Frame for buttons
        btn_frame = ttk.Frame(self.tab_logs)
        btn_frame.pack(fill="x", side="top", padx=5, pady=5)

        ttk.Button(
            btn_frame,
            text="Generate Audit Report",
            command=self.generate_report
        ).pack(side="left", padx=5)

        ttk.Button(
            btn_frame,
            text="Set Report Directory",
            command=self.set_report_directory
        ).pack(side="left", padx=5)

        self.log_box = tk.Text(self.tab_logs, bg="#0f172a", fg="#e5e7eb", font=("Consolas", 10))
        self.log_box.pack(fill="both", expand=True)

    def build_help_tab(self):
        # Help Content Container
        help_text = tk.Text(self.tab_help, wrap="word", font=("Segoe UI", 11), bg="#f8fafc", fg="#1e293b", padx=20,
                            pady=20)
        help_scroll = ttk.Scrollbar(self.tab_help, command=help_text.yview)
        help_text.configure(yscrollcommand=help_scroll.set)

        help_scroll.pack(side="right", fill="y")
        help_text.pack(side="left", fill="both", expand=True)

        content = """ADVANCED ENDPOINT MONITORING FRAMEWORK - USER GUIDE
=====================================================

Welcome to the Advanced USB & Mobile Endpoint Monitoring Framework. This tool is designed to help system administrators and security professionals monitor external data transfers and prevent unauthorized data exfiltration.

How It Works:
-------------
The application runs several continuous background threads that monitor your Windows system for hardware changes and file system modifications.

1. USB Devices Tab
• Purpose: Tracks standard USB Mass Storage devices (Flash drives, External HDDs).
• What you see: The drive letter assigned, the Hardware ID (VID/PID), the device Serial Number, and the exact time it was connected or disconnected.

2. Mobile (MTP) Tab
• Purpose: Tracks mobile devices connecting via Media Transfer Protocol (Smartphones, Tablets, Digital Cameras).
• Why it matters: MTP devices do not get a standard drive letter (like D: or E:), making them invisible to standard monitoring tools. This tab specifically catches Android/iOS devices plugging into the machine.

3. File Activity Tab
• Purpose: Acts as a Data Loss Prevention (DLP) mechanism.
• How it works: It takes invisible "snapshots" of your critical system folders (Desktop, Downloads, Documents) and any connected USB drives. If a file is copied from the system to the USB, or vice versa, it will log the event here. It also tracks if a file on the USB is modified, renamed, or deleted.

4. Logs Tab & Reporting
• Purpose: Provides a raw, real-time chronological view of all system events.
• Audit Reports: Use the "Set Report Directory" button to choose where to save your logs. Then use the "Generate Audit Report" button to create a formatted, time-stamped text file containing all current session data. This is useful for compliance, auditing, or forensic analysis.

Best Practices for Monitoring:
------------------------------
• Leave the application running in the background to ensure all snapshots and file transfers are captured accurately.
• Always generate an Audit Report before closing the application if you need to retain the session's monitoring data.
"""
        help_text.insert("1.0", content)

        # Add some basic text tagging to make headers bold
        help_text.tag_configure("bold", font=("Segoe UI", 12, "bold"))
        help_text.tag_add("bold", "1.0", "2.0")
        help_text.tag_add("bold", "6.0", "7.0")
        help_text.tag_add("bold", "10.0", "10.15")
        help_text.tag_add("bold", "15.0", "15.18")
        help_text.tag_add("bold", "21.0", "21.18")
        help_text.tag_add("bold", "26.0", "26.21")
        help_text.tag_add("bold", "32.0", "33.0")

        # Disable editing so it acts as a read-only guide
        help_text.config(state=tk.DISABLED)

    def log(self, msg):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_box.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_box.see(tk.END)

    # ================= AUDIT REPORT LOGIC =================
    def set_report_directory(self):
        dir_path = filedialog.askdirectory(title="Select Folder for Audit Reports")
        if dir_path:
            self.report_dir = dir_path
            self.log(f"Report directory set to: {dir_path}")

    def generate_report(self):
        # If no directory is set, ask for one first
        if not self.report_dir:
            self.set_report_directory()
            if not self.report_dir:  # User cancelled
                return

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"Audit_Report_{timestamp}.txt"
        file_path = os.path.join(self.report_dir, filename)

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("====================================================\n")
                f.write(f"ENDPOINT AUDIT REPORT - {datetime.now()}\n")
                f.write("====================================================\n\n")

                f.write("--- 1. USB DEVICE HISTORY ---\n")
                f.write(f"{'Drive':<10} {'VID:PID':<15} {'Serial':<30} {'Status':<15} {'Time'}\n")
                for item in self.usb_table.get_children():
                    v = self.usb_table.item(item)['values']
                    f.write(f"{v[0]:<10} {v[1]:<15} {v[2]:<30} {v[3]:<15} {v[4]}\n")

                f.write("\n--- 2. CONNECTED MTP DEVICES ---\n")
                for entry in self.mtp_box.get(0, tk.END):
                    f.write(f"- {entry}\n")

                f.write("\n--- 3. FILE ACTIVITY LOG ---\n")
                f.write(f"{'Event':<20} {'Time':<15} {'Location':<15} {'File'}\n")
                for item in self.file_table.get_children():
                    v = self.file_table.item(item)['values']
                    f.write(f"{v[0]:<20} {v[3]:<15} {v[2]:<15} {v[1]}\n")

                f.write("\n--- 4. RAW SYSTEM LOGS ---\n")
                f.write(self.log_box.get("1.0", tk.END))

            messagebox.showinfo("Report Generated", f"Audit report saved automatically to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {e}")

    # ================= SNAPSHOT LOGIC (usb10.py) =================
    def snapshot_files(self, base):
        snap = {}
        try:
            for r, _, files in os.walk(base):
                for f in files:
                    p = os.path.join(r, f)
                    try:
                        s = os.stat(p)
                        snap[p] = (s.st_size, s.st_mtime)
                    except:
                        pass
        except:
            pass
        return snap

    def snapshot_system(self):
        snap = {}
        for d in SYSTEM_DIRS:
            if os.path.exists(d):
                snap.update(self.snapshot_files(d))
        return snap

    # ================= FILE CLASSIFICATION (FROM usb10.py) =================
    def classify_usb_changes(self, old, new, drive):
        old_set, new_set = set(old), set(new)
        added, removed = new_set - old_set, old_set - new_set

        for f in old_set & new_set:
            if old[f] != new[f]:
                self.record_file_event("MODIFIED (USB)", f, drive)

        renamed = set()
        for r in removed:
            for a in added:
                if old[r] == new[a]:
                    self.record_file_event("RENAMED (USB)", f"{r} → {a}", drive)
                    renamed.add(a)

        for a in added - renamed:
            self.record_file_event("SYSTEM → USB COPY", a, drive)

        for r in removed:
            if r not in renamed:
                self.record_file_event("DELETED (USB)", r, drive)

    def detect_usb_to_system(self, old_sys, new_sys, usb_snap, drive):
        for f in new_sys.keys() - old_sys.keys():
            meta = new_sys[f]
            for u in usb_snap:
                if usb_snap[u] == meta:
                    self.record_file_event("USB → SYSTEM COPY", f"{u} → {f}", drive)
                    break

    def record_file_event(self, event, file, location):
        self.file_table.insert("", 0, values=(
            event,
            file,
            location,
            datetime.now().strftime("%H:%M:%S")
        ))
        self.log(f"{event} → {file} [{location}]")

    # ================= FILE ACTIVITY LOOP =================
    def file_activity_loop(self):
        while self.monitoring:
            new_sys = self.snapshot_system()

            for d in list(self.prev_drives):
                if os.path.exists(d):
                    new_usb = self.snapshot_files(d)
                    old_usb = self.usb_snapshots.get(d, {})

                    self.classify_usb_changes(old_usb, new_usb, d)
                    self.detect_usb_to_system(self.system_snapshot, new_sys, old_usb, d)

                    self.usb_snapshots[d] = new_usb

            self.system_snapshot = new_sys
            time.sleep(3)

    # ================= USB =================
    def get_usb_info(self):
        try:
            out = subprocess.check_output(
                "wmic diskdrive where \"InterfaceType='USB'\" get PNPDeviceID",
                shell=True).decode(errors="ignore")
            for l in out.splitlines():
                if "USBSTOR" in l:
                    vid = l.split("VID_")[1][:4] if "VID_" in l else "UNK"
                    pid = l.split("PID_")[1][:4] if "PID_" in l else "UNK"
                    serial = l.split("\\")[-1]
                    return vid, pid, serial
        except:
            pass
        return "UNK", "UNK", "UNK"

    def usb_loop(self):
        while self.monitoring:
            try:
                out = subprocess.check_output(
                    "wmic logicaldisk get caption, drivetype",
                    shell=True).decode(errors="ignore")

                current = set(l.split()[0] for l in out.splitlines() if "2" in l)

                for d in current - self.prev_drives:
                    vid, pid, serial = self.get_usb_info()
                    self.usb_table.insert("", 0, values=(
                        d, f"{vid}:{pid}", serial, "CONNECTED",
                        datetime.now().strftime("%H:%M:%S")
                    ))
                    self.usb_snapshots[d] = self.snapshot_files(d)
                    self.log(f"USB INSERTED → {d}")

                for d in self.prev_drives - current:
                    self.usb_snapshots.pop(d, None)
                    self.log(f"USB REMOVED → {d}")

                self.prev_drives = current
                time.sleep(2)
            except:
                time.sleep(2)

    # ================= MTP =================
    def mtp_loop(self):
        while self.monitoring:
            try:
                out = subprocess.check_output(
                    'wmic path Win32_PnPEntity where "DeviceID like \'USB%\'" get Name',
                    shell=True).decode(errors="ignore")

                current = set(
                    l.strip().lower()
                    for l in out.splitlines()
                    if any(k in l.lower() for k in MTP_KEYWORDS)
                )

                for d in current - self.prev_mtp:
                    self.mtp_box.insert(tk.END, d)
                    self.log(f"MTP CONNECTED → {d}")

                for d in self.prev_mtp - current:
                    self.log(f"MTP REMOVED → {d}")

                self.prev_mtp = current
                time.sleep(3)
            except:
                time.sleep(3)


# ================= RUN =================
if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedEndpointMonitor(root)
    root.mainloop()