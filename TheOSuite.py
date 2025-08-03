import tkinter as tk
from tkinter import messagebox, Listbox, Scrollbar, END
import subprocess
import os
import sys

# Config: Map tool names to their submodule dir and entry script
# Updated based on the repository details and entry points
TOOLS = {
    'oBAC: Broken Access Control Testing Application': {'dir': 'oBAC', 'entry': 'oBAC.py'},
    'oCF: Cryptographic Failure Testing Application': {'dir': 'oCF', 'entry': 'oCF.py'},
    'oIAF: Identification and Authentication Failures Tester': {'dir': 'oIAF', 'entry': 'oIAF.py'},
    'oJSS3: S3 Bucket and JavaScript Endpoint Extractor': {'dir': 'oJSS3', 'entry': 'oJSS3.py'},
    'oLSM: Local Security Monitor': {'dir': 'oLSM', 'entry': 'oLSM.py'},
    'oMITM: Man In The Middle Attack Tester': {'dir': 'oMITM', 'entry': 'oMITM.py'},
    'oPFC: Privacy Framework Checklist': {'dir': 'oPFC', 'entry': 'oPFC.py'},  # Assumed; verify if it's a script
    'oPKI: A Certificate Authority and Certificate Management Utility': {'dir': 'oPKI', 'entry': 'oPKI.py', 'args': ['--gui']},
    'oSDIS: Software and Data Integrity Scanner': {'dir': 'oSDIS', 'entry': 'oSDIS.py'},
    'oSLMF: Security Logging and Monitoring Failures Tester': {'dir': 'oSLMF', 'entry': 'oSLMF.py'},
    'oSMS: Security Misconfiguration Scanner': {'dir': 'oSMS', 'entry': 'oSMS.py'},
    'oSSLC: SSL Certificate Analyzer': {'dir': 'oSSLC', 'entry': 'oSSLC.py'},
    'oSSRF: Server-Side Request Forgery Testing Utility': {'dir': 'oSSRF', 'entry': 'oSSRF.py'},
    'oVOC: Vulnerable and Outdated Components Tester': {'dir': 'oVOC', 'entry': 'gui.py'},
    'oXSS: Enhanced Cross Site Scripting Scanner': {'dir': 'oXSS', 'entry': 'oXSS.py'},
    'paygen: Payload Generator': {'dir': 'paygen', 'entry': 'paygen.py'}
}

def launch_tool(tool_name):
    if tool_name not in TOOLS:
        messagebox.showerror("Error", f"Tool '{tool_name}' not found.")
        return
    
    tool = TOOLS[tool_name]
    base_dir = os.path.dirname(os.path.abspath(__file__))  # Main suite dir
    tool_path = os.path.join(base_dir, tool['dir'], tool['entry'])
    
    if not os.path.exists(tool_path):
        messagebox.showerror("Error", f"Entry script not found: {tool_path}")
        return
    
    try:
        # Launch in new process (non-blocking), including any optional args
        command = [sys.executable, tool_path] + tool.get('args', [])
        subprocess.Popen(command, cwd=os.path.join(base_dir, tool['dir']))
        messagebox.showinfo("Success", f"Launched {tool_name}")
    except Exception as e:
        messagebox.showerror("Launch Error", f"Failed to launch {tool_name}: {str(e)}")

# GUI Setup
root = tk.Tk()
root.title("TheOSuite Central Launcher")
root.geometry("600x400")

label = tk.Label(root, text="Select a tool to launch:", pady=10)
label.pack()

# Listbox for tools with scrollbar
scrollbar = Scrollbar(root)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

listbox = Listbox(root, yscrollcommand=scrollbar.set, height=15, width=80)
for tool in sorted(TOOLS.keys()):
    listbox.insert(END, tool)
listbox.pack(pady=10)

scrollbar.config(command=listbox.yview)

def on_launch():
    selected = listbox.curselection()
    if not selected:
        messagebox.showwarning("Selection", "Please select a tool.")
        return
    tool_name = listbox.get(selected[0])
    launch_tool(tool_name)

launch_btn = tk.Button(root, text="Launch Selected Tool", command=on_launch)
launch_btn.pack(pady=10)

quit_btn = tk.Button(root, text="Quit", command=root.quit)
quit_btn.pack()

root.mainloop()
