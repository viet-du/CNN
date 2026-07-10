import random
import hashlib

# Import các hàm toán học nền tảng từ ECC_math
from ECC_math import secp256k1, Point

class ECC_Asymmetric:
    """
    Hệ thống Mã hóa Bất đối xứng sử dụng Đường cong Elliptic (ECIES logic)
    - Alice tạo một khóa dùng một lần (Ephemeral Key).
    - Dùng khóa bí mật chung (Shared Secret) với Bob để sinh ra Symmetric Key.
    - Mã hóa thông điệp bằng Symmetric Key.
    """
    def __init__(self, curve):
        self.curve = curve
        
    def generate_keypair(self):
        d = random.randrange(1, self.curve.n)
        Q = self.curve.multiply_point(d, self.curve.G)
        return d, Q

    def encrypt(self, message: bytes, receiver_pub_key: Point):
        # Tạo khóa bí mật ngẫu nhiên dùng 1 lần k
        k = random.randrange(1, self.curve.n)
        
        # Ephemeral Public Key (R) để gửi công khai cho Bob
        R = self.curve.multiply_point(k, self.curve.G)
        
        # Shared Secret = k * Q_B
        S = self.curve.multiply_point(k, receiver_pub_key)
        
        # Dùng SHA-256 băm tọa độ x của Shared Secret thành Khóa đối xứng
        shared_secret_bytes = S.x.to_bytes((S.x.bit_length() + 7) // 8, 'big')
        key_hash = hashlib.sha256(shared_secret_bytes).digest()
        
        # Mã hóa thông điệp gốc bằng khóa đối xứng (Stream cipher XOR)
        ciphertext = bytearray()
        for i in range(len(message)):
            ciphertext.append(message[i] ^ key_hash[i % len(key_hash)])
            
        return R, bytes(ciphertext)

    def decrypt(self, R: Point, ciphertext: bytes, receiver_priv_key: int):
        # Shared Secret = d_B * R
        S = self.curve.multiply_point(receiver_priv_key, R)
        
        # Tái tạo Khóa đối xứng từ tọa độ x
        shared_secret_bytes = S.x.to_bytes((S.x.bit_length() + 7) // 8, 'big')
        key_hash = hashlib.sha256(shared_secret_bytes).digest()
        
        # Giải mã khôi phục văn bản gốc
        plaintext = bytearray()
        for i in range(len(ciphertext)):
            plaintext.append(ciphertext[i] ^ key_hash[i % len(key_hash)])
            
        return bytes(plaintext)


if __name__ == "__main__":
    ecc = ECC_Asymmetric(secp256k1)
    
    # Lấy thông điệp từ bàn phím
    user_input = input("Nhập đoạn tin nhắn cần mã hóa: ")
    message_bytes = user_input.encode('utf-8')
    
    msg_len = len(message_bytes)
    msg_hash = hashlib.sha256(message_bytes).hexdigest()
    
    # ------------------ IN KẾT QUẢ TRÌNH BÀY ĐÚNG YÊU CẦU ------------------
    print("\nTEST 3: ELLIPTIC CURVE ASYMMETRIC ENCRYPTION (Alice & Bob)\n")
    
    print(f"Message: {user_input}")
    print(f"Message length: {msg_len} bytes")
    print(f"Message hash (SHA256): {msg_hash}\n")
    
    print("Key Generation:")
    a_priv, a_pub = ecc.generate_keypair()
    print(f"  Alice Private (hex): {hex(a_priv)}")
    print(f"  Alice Public X (hex): {hex(a_pub.x)}")
    print(f"  Alice Public Y (hex): {hex(a_pub.y)}\n")
    
    b_priv, b_pub = ecc.generate_keypair()
    print(f"  Bob Private (hex): {hex(b_priv)}")
    print(f"  Bob Public X (hex): {hex(b_pub.x)}")
    print(f"  Bob Public Y (hex): {hex(b_pub.y)}\n")
    
    print("Alice Encrypts for Bob:")
    R, ciphertext = ecc.encrypt(message_bytes, b_pub)
    print(f"  Ephemeral Public Key X (hex): {hex(R.x)}")
    print(f"  Ephemeral Public Key Y (hex): {hex(R.y)}")
    print(f"  Plaintext Hash: {msg_hash}")
    
    print("Bob Decrypts:")
    decrypted_bytes = ecc.decrypt(R, ciphertext, b_priv)
    decrypted_str = decrypted_bytes.decode('utf-8', errors='ignore')
    print(f"  Decrypted: {decrypted_str}")
    print(f"  Decryption OK: {decrypted_bytes == message_bytes}")
