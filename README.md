# ĐỒ ÁN: HỆ THỐNG XÁC THỰC 2FA VÀ MÃ HÓA ĐA TẦNG
**Công nghệ:** Python Flask, SQLite (NoSQL), AES-256, RSA-2048, HTML/CSS/JS.

## ⚙️ HƯỚNG DẪN CÀI ĐẶT VÀ CHẠY DỰ ÁN

**Bước 1: Khởi tạo môi trường (Khuyến nghị)**
Mở Terminal / Command Prompt tại thư mục dự án và gõ:
python -m venv venv
(Windows): venv\Scripts\activate
(Mac/Linux): source venv/bin/activate

**Bước 2: Cài đặt thư viện**
pip install -r requirements.txt

**Bước 3: Cấu hình hệ thống (.env)**
1. Đổi tên file `.env.example` thành `.env`.
2. Mở file `.env` và điền Gmail của bạn cùng "Mật khẩu ứng dụng" (App Password) để hệ thống có thể gửi mã OTP.

**Bước 4: Khởi động Server**
python app.py

**Bước 5: Truy cập hệ thống (LƯU Ý QUAN TRỌNG)**
Hệ thống được ép chạy trên giao thức HTTPS bảo mật bằng chứng chỉ tự ký (Self-signed Certificate).
👉 Truy cập chính xác đường dẫn: **https://localhost:5001** (Bắt buộc có chữ "s").
👉 Trình duyệt sẽ cảnh báo "Your connection is not private". Bạn hãy bấm **Advanced (Nâng cao)** -> Chọn **Proceed to localhost / Tiếp tục truy cập**.