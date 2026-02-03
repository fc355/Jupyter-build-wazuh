# ขั้นตอนการติดตั้ง Wazuh All-in-One ด้วย Docker
## 1. ข้อกำหนดเบื้องต้น (Prerequisites)
•	ระบบปฏิบัติการ: Ubuntu 20.04 / 22.04

•	สิทธิ์ผู้ดูแลระบบ (sudo)

•	ทรัพยากรขั้นต่ำที่แนะนำ

    o	CPU: 4 vCPU

    o	RAM: 8 GB (ขั้นต่ำ 4 GB)

    o	Disk: 50 GB ขึ้นไป
## 2. เตรียมระบบ VM07
### 2.1 อัปเดตระบบ
```
sudo apt update && sudo apt upgrade -y
```
### 2.2 ตั้งค่า kernel parameter สำหรับ Wazuh Indexer
```
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```
## 3. ติดตั้ง Docker และ Docker Compose
### 3.1 ติดตั้ง Docker
```
sudo apt install -y docker.io
sudo systemctl enable docker
sudo systemctl start docker
```
### 3.2 ติดตั้ง Docker Compose (plugin)
```
sudo apt install -y docker-compose-plugin
```
### 3.3 ตรวจสอบเวอร์ชัน
```
docker --version
docker compose version
```
## 4. ดาวน์โหลด Wazuh Docker All-in-One
### 4.1 สร้างโฟลเดอร์สำหรับติดตั้ง
```
mkdir -p ~/wazuh-docker
cd ~/wazuh-docker
```
### 4.2 Clone repository ทางการของ Wazuh
[git clone] (https://github.com/wazuh/wazuh-docker.git)
```
cd wazuh-docker/single-node
```
โฟลเดอร์ single-node คือรูปแบบ All-in-One (ทุก service อยู่ในเครื่องเดียว)
## 5. ติดตั้งและเริ่มต้นระบบ Wazuh
### 5.1 เริ่ม container ทั้งหมด
```
docker compose up -d
```
ใช้เวลาประมาณ 5–10 นาทีในการ pull image และ initial service
### 5.2 ตรวจสอบสถานะ container
```
docker ps
```
ควรพบ container หลักดังนี้

•	wazuh-manager

•	wazuh-indexer

•	wazuh-dashboard
## 6. เข้าใช้งาน Wazuh Dashboard
### 6.1 URL สำหรับเข้าใช้งาน
https://<IP_VM07>
### 6.2 ข้อมูลเข้าสู่ระบบเริ่มต้น
Username: admin

Password: admin

หมายเหตุ: เป็น HTTPS แบบ self-signed certificate แนะนำให้เปลี่ยนรหัสผ่านทันทีหลังเข้าใช้งาน
## 7. ตรวจสอบสถานะและ Log
### 7.1 ดู log ของระบบทั้งหมด
```
docker compose logs -f
```
### 7.2 ดู log เฉพาะ Wazuh Manager
```
docker logs wazuh.manager
```
## 8. พอร์ตที่ใช้งาน (กรณีมี Firewall)
|Service |	Port|
|--- |--- |
|Wazuh Dashboard |	443|
|Agent (Log/Alert) |	1514/udp|
|Agent Registration |	1515/tcp|
|Wazuh API |	55000|

