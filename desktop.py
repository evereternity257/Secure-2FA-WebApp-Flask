import threading
import webview
from app import app  # Import app từ file app.py

def start_flask():
    # Chạy Flask ở HTTP thường (bỏ ssl_context đi để PyWebView không bị lỗi bảo mật chứng chỉ)
    app.run(host='127.0.0.1', port=5001, debug=False, use_reloader=False)

if __name__ == '__main__':
    # Khởi động Flask trong luồng ngầm
    t = threading.Thread(target=start_flask)
    t.daemon = True
    t.start()

    # Tạo cửa sổ Desktop App trỏ tới http://127.0.0.1:5001/login
    webview.create_window(
        'Hệ thống Bảo mật Mật mã học 2FA', 
        'http://127.0.0.1:5001/login', 
        width=1200, 
        height=800,
        min_size=(800, 600)
    )
    webview.start()