# CNN
Mã hoá
# Dự án An Toàn Thông Tin (Cyber Security Project)

Dự án này chứa mã nguồn Python mô phỏng và cài đặt từ đầu (from scratch) các thuật toán mật mã cơ bản trong bộ môn An Toàn Thông Tin. Các thuật toán được chia thành 3 nhóm chính: Mã hóa đối xứng, Mã hóa bất đối xứng (Hệ mật đường cong Elliptic - ECC), và Chữ ký số.

## Cấu trúc dự án

```text
Project-cyper-security/
│
├── AES-128/                  # Nhóm thuật toán mã hóa đối xứng & Hàm băm
│   ├── AES-128.py            # Cài đặt chi tiết thuật toán mã hóa khối AES-128
│   └── Hash-256.py           # Cài đặt thuật toán băm dữ liệu SHA-256
│
├── Bat-doi-xung/             # Nhóm thuật toán mã hóa bất đối xứng (dựa trên ECC)
│   ├── EC_asymmetric.py      # Cài đặt mã hóa và giải mã bất đối xứng bằng đường cong Elliptic
│   ├── ECC_math.py           # Các phép toán cơ bản trên hệ mật đường cong Elliptic (cộng điểm, nhân điểm...)
│   └── ECCDH.py              # Cài đặt thuật toán trao đổi khóa Elliptic-Curve Diffie-Hellman
│
├── Chukyso/                  # Nhóm thuật toán chữ ký số
│   ├── DSA.py                # Cài đặt thuật toán chữ ký số DSA (Digital Signature Algorithm)
│   └── dsa_param.pem         # File chứa các tham số được sinh ra cho thuật toán DSA
│
└── 1.ipynb                   # Jupyter Notebook (có thể dùng để nháp, demo hoặc test thuật toán)
```

## Chi tiết các Module

### 1. AES-128 & Hàm băm (Thư mục `AES-128`)
*   **AES-128 (`AES-128.py`)**: Cài đặt thuật toán mã hóa tiên tiến AES với kích thước khóa 128-bit. Bao gồm các vòng (rounds) với các phép biến đổi như SubBytes, ShiftRows, MixColumns và AddRoundKey.
*   **SHA-256 (`Hash-256.py`)**: Hàm băm mật mã an toàn, tạo ra chuỗi băm 256-bit (32 byte), thường được dùng kết hợp để kiểm tra tính toàn vẹn của dữ liệu.

### 2. Mật mã Bất đối xứng - Elliptic Curve (Thư mục `Bat-doi-xung`)
Hệ mật đường cong Elliptic (ECC) cung cấp độ an toàn cao với kích thước khóa nhỏ hơn đáng kể so với hệ mật RSA với cùng một mức an toàn.
*   **Toán học ECC (`ECC_math.py`)**: Nền tảng cốt lõi định nghĩa các phép toán trên trường hữu hạn của đường cong (Modular arithmetic, Point addition, Point doubling).
*   **Mã hóa/Giải mã (`EC_asymmetric.py`)**: Ứng dụng toán học ECC để thực hiện việc mã hóa thông điệp bằng khóa công khai và giải mã bằng khóa bí mật.
*   **Trao đổi khóa (`ECCDH.py`)**: Cài đặt thuật toán Diffie-Hellman trên đường cong Elliptic, cho phép hai bên thiết lập một khóa bí mật chung thông qua một kênh truyền không an toàn.

### 3. Chữ ký số (Thư mục `Chukyso`)
*   **DSA (`DSA.py`)**: Cài đặt chuẩn chữ ký số DSA. Cung cấp các chức năng: sinh khóa (Key Generation), tạo chữ ký (Signing) và xác minh chữ ký (Verification). Đảm bảo tính xác thực và tính chống chối bỏ của tài liệu.
*   **Tham số DSA (`dsa_param.pem`)**: Tệp tin lưu trữ các tham số p, q, g được tạo ra trong quá trình thiết lập hệ thống chữ ký số DSA để tái sử dụng.

## Yêu cầu môi trường
*   **Ngôn ngữ**: Python 3.x
*   Không yêu cầu thư viện mã hóa bên ngoài (trừ khi dùng các thư viện toán học cơ bản tích hợp sẵn của Python), vì các thuật toán được viết thủ công nhằm mục đích học tập và nghiên cứu.

## Hướng dẫn sử dụng
Để chạy thử các thuật toán, bạn có thể chạy trực tiếp các file Python thông qua terminal/command prompt. Ví dụ:
```bash
cd AES-128
python AES-128.py
```
*(Vui lòng xem trực tiếp trong mỗi file mã nguồn để biết cách gọi hàm hoặc xem phần `if __name__ == "__main__":` để biết kịch bản test đã được viết sẵn)*
