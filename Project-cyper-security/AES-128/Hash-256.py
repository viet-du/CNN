import struct

# Khởi tạo hằng số K (64 giá trị đầu tiên của phần phân số của căn bậc 3 của 64 số nguyên tố đầu tiên)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Các hàm thao tác bit cơ bản (chuẩn 32-bit)
def rotr(x, n):
    """Xoay phải (Right rotate) n bit cho số nguyên 32-bit"""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def ch(x, y, z):
    """Hàm Choose (Lựa chọn)"""
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    """Hàm Majority (Đa số)"""
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def gamma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def gamma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

def sha256(message: bytes) -> bytes:
    """
    Hàm băm SHA-256.
    Nhận đầu vào là bytes, trả về mã băm 256-bit (32 bytes).
    """
    # Khởi tạo giá trị hash ban đầu (H0 - H7) (Phần phân số của căn bậc 2 của 8 số nguyên tố đầu tiên)
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    # 1. Tiền xử lý (Padding)
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8

    # Thêm bit '1' (byte 0x80)
    message += b'\x80'
    
    # Thêm các byte '0' sao cho chiều dài thông điệp mod 64 bằng 56 (tương đương mod 512 bit bằng 448)
    # (64 bytes = 512 bits, 56 bytes = 448 bits)
    while (len(message) % 64) != 56:
        message += b'\x00'
        
    # Nối thêm chiều dài gốc (dưới dạng 64-bit integer, Big Endian)
    message += struct.pack(">Q", original_bit_len)

    # 2. Xử lý thông điệp theo từng khối 512-bit (64 bytes)
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        
        # Mở rộng 16 words (32-bit) thành 64 words trong Message Schedule Array (W)
        w = [0] * 64
        # Lấy 16 từ 32-bit (Big Endian) đầu tiên
        for j in range(16):
            w[j] = struct.unpack(">I", chunk[j*4:(j+1)*4])[0]
            
        # Tính toán 48 words còn lại
        for j in range(16, 64):
            s0 = gamma0(w[j-15])
            s1 = gamma1(w[j-2])
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xFFFFFFFF

        # Khởi tạo các biến làm việc cho khối hiện tại
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Vòng lặp nén chính (64 vòng)
        for j in range(64):
            s1 = sigma1(e)
            ch_val = ch(e, f, g)
            temp1 = (h + s1 + ch_val + K[j] + w[j]) & 0xFFFFFFFF
            s0 = sigma0(a)
            maj_val = maj(a, b, c)
            temp2 = (s0 + maj_val) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Cộng dồn kết quả của chunk vào các giá trị hash tổng (mod 2^32)
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

    # 3. Tạo kết quả băm cuối cùng bằng cách nối các phần 32-bit lại với nhau (Big Endian)
    return struct.pack(">IIIIIIII", h0, h1, h2, h3, h4, h5, h6, h7)

if __name__ == "__main__":
    print("=== Chương trình tạo mã băm SHA-256 ===")
    ho_ten = input("Nhập tin nhắn:  ").strip()
    
    if ho_ten:
        # Chuyển chuỗi thành bytes sử dụng UTF-8
        data = ho_ten.encode('utf-8')
        hash_result = sha256(data)
        
        print(f"\nDữ liệu đầu vào: {ho_ten}")
        print(f"Mã băm SHA-256 (Hex): {hash_result.hex()}")
        
        # In ra 16 bytes đầu tiên (dùng làm key AES-128)
        print(f"128 bit (16 bytes) đầu tiên sẽ dùng cho khóa AES: {hash_result[:16].hex()}")
    else:
        print("Vui lòng nhập tên hợp lệ!")
