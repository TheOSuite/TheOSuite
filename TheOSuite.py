import tkinter as tk
from tkinter import messagebox, Listbox, Scrollbar, END
import subprocess
import os
import sys

# Config: Map tool names to their submodule dir and entry script
# Update this dict based on your repos (e.g., from READMEs: oXSS -> 'oXSS.py', oVOC -> 'gui.py')
TOOLS = {
    'oXSS: Enhanced XSS Scanner': {'dir': 'oXSS', 'entry': 'oXSS.py'},
    'oVOC: Vulnerable Components Tester': {'dir': 'oVOC', 'entry': 'gui.py'},
    'oPFC: Privacy Framework Checklist': {'dir': 'oPFC', 'entry': 'main.py'},  # Assume; verify
    'oIAF: Auth Failures Tester': {'dir': 'oIAF', 'entry': 'oIAF.py'},  # Assume; verify
    'oSSRF: SSRF Tester': {'dir': 'oSSRF', 'entry': 'oSSRF.py'},
    'oSLMF: Logging Failures Tester': {'dir': 'oSLMF', 'entry': 'oSLMF.py'},
    'oBAC: Access Control Tester': {'dir': 'oBAC', 'entry': 'oBAC.py'},
    'oSSLC: SSL Analyzer': {'dir': 'oSSLC', 'entry': 'oSSLC.py'},
    'oMITM: MITM Tester': {'dir': 'oMITM', 'entry': 'oMITM.py'},
    'oPKI: PKI Manager': {'dir': 'oPKI', 'entry': 'oPKI.py'},
    'oLSM: Local Security Monitor': {'dir': 'oLSM', 'entry': 'oLSM.py'},
    'oJSS3: S3/JS Extractor': {'dir': 'oJSS3', 'entry': 'oJSS3.py'},
    'paygen: Payload Generator': {'dir': 'paygen', 'entry': 'paygen.py'},
    'oSMS: Misconfig Scanner': {'dir': 'oSMS', 'entry': 'oSMS.py'},
    'oSDIS: Integrity Scanner': {'dir': 'oSDIS', 'entry': 'oSDIS.py'},
    'oCF: Crypto Failures Tester': {'dir': 'oCF', 'entry': 'oCF.py'},
}

def launch_tool(tool_name):
    if tool_name not in TOOLS:
        messagebox.showerror("Error", f"Tool '{tool_name}' not found.")
        return
    
    tool = TOOLS[tool_name]
    base_dir = os.path.dirname(os.path.abspath(__file__))  # MainSuite dir
    tool_path = os.path.join(base_dir, tool['dir'], tool['entry'])
    
    if not os.path.exists(tool_path):
        messagebox.showerror("Error", f"Entry script not found: {tool_path}")
        return
    
    try:
        # Launch in new process (non-blocking)
        subprocess.Popen([sys.executable, tool_path], cwd=os.path.join(base_dir, tool['dir']))
        messagebox.showinfo("Success", f"Launched {tool_name}")
    except Exception as e:
        messagebox.showerror("Launch Error", f"Failed to launch {tool_name}: {str(e)}")

# GUI Setup
root = tk.Tk()
root.title("TheOSuite Central Launcher")
root.geometry("400x400")

label = tk.Label(root, text="Select a tool to launch:", pady=10)
label.pack()

# Listbox for tools with scrollbar
scrollbar = Scrollbar(root)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

listbox = Listbox(root, yscrollcommand=scrollbar.set, height=15, width=50)
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
