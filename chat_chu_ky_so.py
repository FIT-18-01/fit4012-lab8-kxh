import socket
import threading
import os
from datetime import datetime
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from secure_transfer_utils import (
    build_sender_payload, open_receiver_payload,
    load_public_key, load_private_key, recv_secure_packet, recv_exact,
    parse_secure_packet
)

# Cấu hình đường dẫn
MY_PRIVATE_KEY = "keys/my_private.pem"
THEIR_PUBLIC_KEY = "keys/their_public.pem"
LOG_FILE = "logs/chat_evidence.log"

def write_evidence_log(action, ip, message, status, hash_val="N/A"):
    """Hàm tự động ghi log kèm MÃ BĂM làm bằng chứng nộp Lab"""
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Rút gọn mã băm cho dễ nhìn trong log (chỉ lấy 16 ký tự đầu và cuối)
    if hash_val != "N/A" and len(hash_val) > 32:
        hash_display = f"{hash_val[:16]}...{hash_val[-16:]}"
    else:
        hash_display = hash_val

    log_line = f"[{timestamp}] [{action}] | IP: {ip} | Trạng thái: {status} | Hash: {hash_display} | Nội dung: {message}\n"
    
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)

def receiver_thread(my_port):
    """Luồng nhận tin nhắn và xác thực chữ ký số trên BẢN MÃ"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", my_port))
    server.listen(5)
    
    my_private_key = load_private_key(MY_PRIVATE_KEY)
    their_public_key = load_public_key(THEIR_PUBLIC_KEY)
    
    while True:
        try:
            conn, addr = server.accept()
            with conn:
                packet = recv_secure_packet(conn)
                signature = recv_exact(conn, 256)
                
                encrypted_des_key, ciphertext_with_iv, received_hash = parse_secure_packet(packet)
                
                # Băm BẢN MÃ và lấy chuỗi Hex của mã băm
                hash_obj = SHA256.new(ciphertext_with_iv)
                hash_hex = hash_obj.hexdigest()
                
                try:
                    pkcs1_15.new(their_public_key).verify(hash_obj, signature)
                    signature_ok = True
                except (ValueError, TypeError):
                    signature_ok = False
                
                # Giải mã lấy bản rõ
                plaintext, integrity_ok = open_receiver_payload(packet, my_private_key)
                
                # Xử lý kết quả
                msg_decoded = plaintext.decode('utf-8', errors='ignore')
                
                if integrity_ok and signature_ok:
                    status = "✅ Xác minh chữ ký hợp lệ"
                    print(f"\r[📩 Nhận từ {addr[0]} | {status}]: {msg_decoded}")
                elif not signature_ok:
                    status = "❌ BÁO ĐỘNG: Chữ ký số giả mạo!"
                    print(f"\r[{status}]")
                else:
                    status = "❌ BÁO ĐỘNG: Dữ liệu bị thay đổi!"
                    print(f"\r[{status}]")
                
                # Lưu vào file log kèm MÃ BĂM
                write_evidence_log("NHẬN", addr[0], msg_decoded, status, hash_hex)
                print("Nhập tin nhắn: ", end="", flush=True) 
        except Exception as e:
            pass

def main():
    print("=== CHAT E2EE CHỮ KÝ SỐ (Có lưu Log Mã Băm) ===")
    my_port = int(input("[?] Nhập Port máy BẠN mở để nhận tin: "))
    dest_ip = input("[?] Nhập IP của máy KIA: ")
    dest_port = int(input("[?] Nhập Port máy KIA đang mở: "))

    write_evidence_log("HỆ THỐNG", "Local", f"Bắt đầu phiên chat tại port {my_port} với {dest_ip}:{dest_port}", "Khởi động")

    t = threading.Thread(target=receiver_thread, args=(my_port,), daemon=True)
    t.start()
    
    print(f"\n[*] Đang lắng nghe tại cổng {my_port}...")
    print("[*] Sẵn sàng nhắn tin! (Gõ 'exit' để thoát)\n")
    
    their_public_key = load_public_key(THEIR_PUBLIC_KEY)
    my_private_key = load_private_key(MY_PRIVATE_KEY)

    while True:
        msg = input("Nhập tin nhắn: ")
        if msg.lower() == 'exit':
            write_evidence_log("HỆ THỐNG", "Local", "Kết thúc phiên chat", "Đóng kết nối")
            break
        if not msg.strip():
            continue
            
        plaintext = msg.encode("utf-8")
        
        # Đóng gói và Ký số
        packet, des_key, ciphertext_with_iv, plaintext_hash = build_sender_payload(plaintext, their_public_key)
        
        # Lấy mã băm của bản mã để lưu log và ký
        hash_obj = SHA256.new(ciphertext_with_iv)
        hash_hex = hash_obj.hexdigest()
        signature = pkcs1_15.new(my_private_key).sign(hash_obj)
        
        # Gửi đi và GHI LOG
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((dest_ip, dest_port))
                s.sendall(packet + signature)
            
            # Lưu vào file log kèm MÃ BĂM
            write_evidence_log("GỬI", dest_ip, msg, "✅ Đã mã hóa và Ký số", hash_hex)
        except Exception as e:
            print(f"[-] Lỗi gửi tin: Không thể kết nối tới {dest_ip}:{dest_port}")
            write_evidence_log("LỖI GỬI", dest_ip, msg, "Không thể kết nối", "N/A")

if __name__ == "__main__":
    main()