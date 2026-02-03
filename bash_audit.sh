# ฟังก์ชันที่จะรันทุกครั้งหลังกด Enter
log_bash_command() {
    # ดึงคำสั่งล่าสุด
    local cmd=$(history 1 | sed "s/^[ ]*[0-9]\+[ ]*//")
    local user=${JUPYTERHUB_USER:-unknown}
    local time=$(date -Iseconds)
    
    if [ -n "$cmd" ]; then
        # สร้าง JSON String
        local log="{\"timestamp\": \"$time\", \"event_type\": \"terminal\", \"user\": \"$user\", \"code\": \"$cmd\", \"app\": \"jupyter-audit-system\"}"
        
        # ส่งไปที่ /proc/1/fd/1 (Stdout ของ Main Process)
        # หมายเหตุ: ในบาง Environment อาจติด Permission ถ้าไม่ได้ ให้เปลี่ยนเป็น logger
        echo "$log" >> /proc/1/fd/1 2>/dev/null || true
    fi
}

# สั่งให้รันฟังก์ชันข้างบนทุกครั้งที่ Command จบ
export PROMPT_COMMAND="log_bash_command"