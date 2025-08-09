import json
import logging
import subprocess
import threading
import time
from datetime import datetime, timedelta
from scapy.all import sniff, IP, ICMP, TCP, UDP

# --- 로깅 설정 ---
logging.basicConfig(filename='dos_detection.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


class DosDefender:
    """
    DoS 공격을 탐지하고 동적으로 방어하는 클래스.
    - 설정 파일(config.json)을 통해 임계값 및 차단 시간 관리
    - 임계값 기반의 패킷 수 모니터링
    - 공격 감지 시 iptables를 이용한 자동 IP 차단
    - 일정 시간 후 차단된 IP 자동 해제
    """

    def __init__(self, config_path='config.json'):
        self.packet_count = 0
        self.start_time = datetime.now()
        self.blocked_ips = {}  # {ip: block_end_time}
        self.load_config(config_path)

    def load_config(self, config_path):
        """설정 파일(config.json)을 로드합니다."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                self.threshold = config.get('threshold', 100)
                self.block_duration_minutes = config.get(
                    'block_duration_minutes', 5)
                self.interface = config.get(
                    'interface', None)  # None이면 모든 인터페이스 감시
            print(
                f"Config loaded: Threshold={self.threshold} pps, Block Duration={self.block_duration_minutes} mins")
            logging.info(
                f"Configuration loaded successfully from {config_path}")
        except FileNotFoundError:
            print("Error: config.json not found. Using default settings.")
            logging.error("config.json not found. Using default settings.")
            self.threshold = 100
            self.block_duration_minutes = 5
            self.interface = None

    def run_iptables_command(self, command):
        """subprocess를 사용하여 iptables 명령어를 실행합니다."""
        try:
            result = subprocess.run(
                command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            logging.info(
                f"iptables command executed successfully: {' '.join(command)}")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(
                f"Failed to execute iptables command: {' '.join(command)}. Error: {e.stderr}")
            print(f"Error executing iptables: {e.stderr}")
            return False

    def block_ip(self, ip):
        """지정된 IP 주소를 iptables를 사용하여 차단합니다."""
        if ip not in self.blocked_ips:
            print(f"Blocking IP: {ip}")
            command = ['sudo', 'iptables', '-A',
                       'INPUT', '-s', ip, '-j', 'DROP']
            if self.run_iptables_command(command):
                self.blocked_ips[ip] = datetime.now(
                ) + timedelta(minutes=self.block_duration_minutes)
                print(
                    f"Added iptables rule to drop packets from {ip} for {self.block_duration_minutes} minutes.")

    def unblock_ip(self, ip):
        """지정된 IP 주소의 차단을 해제합니다."""
        print(f"Unblocking IP: {ip}")
        command = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
        self.run_iptables_command(command)

    def manage_blocks(self):
        """주기적으로 차단 목록을 확인하고 만료된 IP를 해제합니다."""
        while True:
            now = datetime.now()
            # 안전한 순회를 위해 키 리스트 복사
            for ip in list(self.blocked_ips.keys()):
                if now > self.blocked_ips[ip]:
                    self.unblock_ip(ip)
                    del self.blocked_ips[ip]
            time.sleep(60)  # 1분마다 체크

    def detect_dos(self, packet):
        """패킷을 분석하여 DoS 공격을 탐지합니다."""
        now = datetime.now()

        if now - self.start_time > timedelta(seconds=1):
            if self.packet_count > self.threshold:
                if IP in packet:
                    attacker_ip = packet[IP].src
                    attack_type = "Unknown"
                    if ICMP in packet:
                        attack_type = "ICMP Flood"
                    elif TCP in packet:
                        attack_type = "TCP Flood"
                    elif UDP in packet:
                        attack_type = "UDP Flood"

                    log_msg = f"DoS Attack Detected! Type: {attack_type}, PPS: {self.packet_count}, Attacker IP: {attacker_ip}"
                    print(log_msg)
                    logging.warning(log_msg)

                    self.block_ip(attacker_ip)

            self.packet_count = 0
            self.start_time = now

        if IP in packet:
            self.packet_count += 1

    def start_defense(self):
        """공격 탐지 및 방어 시스템을 시작합니다."""
        # 백그라운드에서 차단 관리 스레드 실행
        block_manager_thread = threading.Thread(
            target=self.manage_blocks, daemon=True)
        block_manager_thread.start()

        print("Starting DoS Defender...")
        logging.info("DoS Defender started.")

        # 패킷 캡처 시작
        sniff(iface=self.interface, filter="ip", prn=self.detect_dos, store=0)


if __name__ == "__main__":
    defender = DosDefender()
    defender.start_defense()
