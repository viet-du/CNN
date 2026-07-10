import os
import sys
import importlib.util
import random

# =====================================================================
# 1. LIÊN KẾT VỚI HÀM BĂM SHA-256 (TỪ THƯ MỤC AES-128)
# =====================================================================
current_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(current_dir)
hash_module_path = os.path.join(project_dir, "AES-128", "Hash-256.py")

spec = importlib.util.spec_from_file_location("Hash_256", hash_module_path)
hash_256 = importlib.util.module_from_spec(spec)
sys.modules["Hash_256"] = hash_256
spec.loader.exec_module(hash_256)

# =====================================================================
# 2. TOÁN HỌC NỀN TẢNG
# =====================================================================
def mod_inverse(k, m):
    """
    Tính nghịch đảo modulo bằng thuật toán Euclid mở rộng.
    Trả về x sao cho (k * x) % m == 1
    """
    if k == 0:
        raise ZeroDivisionError('Không tồn tại nghịch đảo cho 0.')
    if k < 0:
        return m - mod_inverse(-k, m)

    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = m, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    if old_r != 1:
        raise ValueError('Không tồn tại nghịch đảo modulo.')

    return old_s % m

# =====================================================================
# 3. THAM SỐ HỆ THỐNG DSA (RFC 5114 - Group 24: 2048-bit p, 256-bit q)
# =====================================================================
# Tham số siêu an toàn được chuẩn hóa sẵn để không phải chờ máy tính tìm số nguyên tố khổng lồ
DSA_P_HEX = "cd95011a0e2c2b3438bf3f6646c3e6830e123695ae0620e74e14f1004441bf03f0ec624a7eda98fbe140457b5158f733405280dc57702d8a2ee7aa6f00b05d13f38081f8e6c15e987b908bcd4848940e17f7dbc5476d130edc74030a60eef6d67f41cf7136cf62f9882923872ffc28dae13c393010adc8390a5dfdd13f0760bd"
DSA_Q_HEX = "a4035e286bdc9ba351dfd0646b667620947ad0eeacc001ddce979f9d"
DSA_G_HEX = "092693c7818f65f59cd8db42dd978f9c6cd0f5e5f65014bd571bf04d49fac3634f39b512c5a65680d87e829a0f70eab091722898c46d18c9a5eca22dba41a6ac5354d2e26589ac56fcda497529802933a17da2bd66dd940a2fc6202326dd92a502f05b22d7c25fae2c75de40b85d0cd6f484909c2a8245b3502be501a4577896"

# =====================================================================
# 4. LỚP ĐIỀU KHIỂN DSA (Digital Signature Algorithm)
# =====================================================================
class DSA:
    def __init__(self):
        # Chuyển đổi tham số từ Hex sang số nguyên Python
        self.p = int(DSA_P_HEX, 16)
        self.q = int(DSA_Q_HEX, 16)
        self.g = int(DSA_G_HEX, 16)

    def generate_keypair(self):
        """Sinh cặp khóa (Private x, Public y)"""
        # 1. Khóa riêng x: 0 < x < q
        x = random.randrange(1, self.q)
        
        # 2. Khóa công khai y: y = g^x (mod p)
        # Sử dụng hàm pow() của Python cực kỳ tối ưu cho tính toán modulo lũy thừa
        y = pow(self.g, x, self.p)
        
        return x, y

    def _hash_message(self, message: bytes) -> int:
        """Sử dụng SHA-256 từ tệp Hash-256.py và chuyển thành số nguyên"""
        hash_bytes = hash_256.sha256(message)
        h = int.from_bytes(hash_bytes, byteorder='big')
        
        # Nếu số bit của hash lớn hơn q, ta phải cắt đi. (Ở đây SHA-256 = 256-bit, q = 256-bit nên vừa khít).
        # Nhưng để an toàn ta vẫn mod q.
        return h % self.q

    def sign(self, message: bytes, private_key: int):
        """Ký số thông điệp bằng khóa riêng x, trả về cặp (r, s)"""
        h = self._hash_message(message)
        
        while True:
            # 1. Chọn số ngẫu nhiên k sao cho 0 < k < q
            k = random.randrange(1, self.q)
            
            # 2. Tính r = (g^k mod p) mod q
            r = pow(self.g, k, self.p) % self.q
            if r == 0:
                continue
                
            # 3. Tính s = k^-1 * (h + x*r) mod q
            try:
                k_inv = mod_inverse(k, self.q)
            except ValueError:
                continue
                
            s = (k_inv * (h + private_key * r)) % self.q
            if s == 0:
                continue
                
            return r, s

    def verify(self, message: bytes, signature: tuple, public_key: int) -> bool:
        """Xác thực chữ ký, trả về True nếu hợp lệ, False nếu từ chối"""
        r, s = signature
        
        # 1. Kiểm tra r và s có nằm trong khoảng hợp lệ 0 < x < q không
        if not (0 < r < self.q and 0 < s < self.q):
            return False
            
        h = self._hash_message(message)
        
        # 2. Tính w = s^-1 mod q
        try:
            w = mod_inverse(s, self.q)
        except ValueError:
            return False
            
        # 3. Tính u1 = (h * w) mod q
        u1 = (h * w) % self.q
        
        # 4. Tính u2 = (r * w) mod q
        u2 = (r * w) % self.q
        
        # 5. Tính v = ((g^u1 * y^u2) mod p) mod q
        # (g^u1 mod p) * (y^u2 mod p) mod p
        term1 = pow(self.g, u1, self.p)
        term2 = pow(public_key, u2, self.p)
        v = ((term1 * term2) % self.p) % self.q
        
        # 6. Chữ ký hợp lệ nếu v == r
        return v == r

# =====================================================================
# 5. KỊCH BẢN KIỂM THỬ GIAO DỊCH TRONG THỰC TẾ
# =====================================================================
if __name__ == "__main__":
    dsa = DSA()
    
    # Cho phép người dùng nhập tin nhắn
    user_input = input("Nhập đoạn tin nhắn cần ký số: ")
    message = user_input.encode('utf-8')
    
    print(f"\nMessage: {message.decode('utf-8')}")
    print("System Parameter Generation:")
    print("  Generating p, q, g...")
    
    # Sinh khóa
    print("Key Pair Generation:")
    x, y_pub = dsa.generate_keypair()
    print(f"  Private x (hex): {hex(x)}")
    print(f"  Public y = g^x mod p (hex): {hex(y_pub)}")
    print(f"  Public key in range (1, p): {1 < y_pub < dsa.p}")
    print()
    
    # Ký số
    print("Message Signing:")
    r, s_sig = dsa.sign(message, x)
    print(f"  Signature r (hex): {hex(r)}")
    print(f"  Signature s (hex): {hex(s_sig)}")
    
    # Xác thực hợp lệ
    print("Signature Verification:")
    is_valid = dsa.verify(message, (r, s_sig), y_pub)
    print(f"  Valid: {is_valid}")
    print()
    
    # ---------------------------------------------------------
    # Invalid Case 1: Tampered Message
    # ---------------------------------------------------------
    print("Invalid Case 1: Tampered Message")
    tampered_message = message + b"_TAMPERED"
    print(f"  Original: {message.decode('utf-8')}")
    print(f"  Tampered: {tampered_message.decode('utf-8')}")
    is_valid_1 = dsa.verify(tampered_message, (r, s_sig), y_pub)
    print(f"  Signature Valid: {is_valid_1} (should be False)")
    print()
    
    # ---------------------------------------------------------
    # Invalid Case 2: Wrong Public Key
    # ---------------------------------------------------------
    print("Invalid Case 2: Wrong Public Key")
    # Tạo một public key sai bằng cách thay đổi giá trị y một chút
    wrong_y = y_pub ^ 1
    print(f"  Original public (hex): {hex(y_pub)[:50]}...")
    print(f"  Wrong public (hex): {hex(wrong_y)[:50]}...")
    is_valid_2 = dsa.verify(message, (r, s_sig), wrong_y)
    print(f"  Signature Valid: {is_valid_2} (should be False)")
    print()
    
    # ---------------------------------------------------------
    # Invalid Case 3: Corrupted Signature (r)
    # ---------------------------------------------------------
    print("Invalid Case 3: Corrupted Signature (r)")
    corrupted_r = r ^ 1
    print(f"  Original r (hex): {hex(r)}")
    print(f"  Corrupted r (hex): {hex(corrupted_r)}")
    is_valid_3 = dsa.verify(message, (corrupted_r, s_sig), y_pub)
    print(f"  Signature Valid: {is_valid_3} (should be False)")
    print()
    
    # ---------------------------------------------------------
    # Invalid Case 4: Corrupted Signature (s)
    # ---------------------------------------------------------
    print("Invalid Case 4: Corrupted Signature (s)")
    corrupted_s = s_sig ^ 1
    print(f"  Original s (hex): {hex(s_sig)}")
    print(f"  Corrupted s (hex): {hex(corrupted_s)}")
    is_valid_4 = dsa.verify(message, (r, corrupted_s), y_pub)
    print(f"  Signature Valid: {is_valid_4} (should be False)")
    print()
