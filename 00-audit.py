import json
import datetime
import os
from IPython import get_ipython

def audit_cell(info):
    try:
        # กรองเซลล์ว่าง
        if not info.raw_cell.strip(): return
        
        log_payload = {
            "timestamp": datetime.datetime.now().isoformat(),
            "event_type": "cell_execution",
            "lang": "python",
            "user": os.environ.get('JUPYTERHUB_USER', 'unknown'),
            "code": info.raw_cell,
            "app": "jupyter-audit-system"
        }
        
        log_msg = (json.dumps(log_payload) + "\n").encode('utf-8')
        
        # --- จุดแก้ (Ninja Mode v2) ---
        # แทนที่จะเขียนลงท่อตัวเอง (os.write(1)) ซึ่งโดนดักได้
        # เราแอบเขียนลงท่อของ (Parent Process) แทน
        try:
            ppid = os.getppid() # หา PID ของ (Jupyter Server)
            with open(f"/proc/{ppid}/fd/1", "wb") as f:
                f.write(log_msg)
        except:
            # ถ้าหาไม่เจอ ให้ลองเขียนลงท่อหลักของ Container (PID 1) ตรงๆ
            try:
                with open("/proc/1/fd/1", "wb") as f:
                    f.write(log_msg)
            except:
                pass
            
    except: pass

ip = get_ipython()
if ip: ip.events.register('pre_run_cell', audit_cell)