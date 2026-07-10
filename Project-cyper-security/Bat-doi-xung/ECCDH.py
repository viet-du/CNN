import os

# Import các phép toán nền tảng từ file ECC_math
from ECC_math import secp256k1, Point

class ECDH:
    """
    Giao thức trao đổi khóa Elliptic Curve Diffie-Hellman (ECDH)
    """
    def __init__(self, curve):
        self.curve = curve

    def generate_keypair(self):
        """
        Sinh cặp khóa (Private Key, Public Key) cho một bên tham gia.
        """
        # Sinh số ngẫu nhiên d (Private Key)
        random_bytes = os.urandom(32)
        d = int.from_bytes(random_bytes, byteorder='big') % (self.curve.n - 1) + 1
        
        # Tính Public Key Q = d * G
        Q = self.curve.multiply_point(d, self.curve.G)
        
        return d, Q

    def compute_shared_secret(self, my_private_key: int, other_public_key: Point):
        """
        Tính toán khóa bí mật chung (Shared Secret).
        Công thức: S = d_mine * Q_others
        """
        # Kiểm tra xem public key của người kia có hợp lệ (nằm trên đường cong) hay không
        if not self.curve.is_on_curve(other_public_key):
            raise ValueError("Public Key của đối tác không nằm trên đường cong hợp lệ!")
        
        if other_public_key.is_infinity():
            raise ValueError("Public Key của đối tác không hợp lệ (Điểm vô cực).")

        # Tính điểm dùng chung S
        shared_point = self.curve.multiply_point(my_private_key, other_public_key)
        
        if shared_point.is_infinity():
            raise ValueError("Lỗi trao đổi khóa: Khóa dùng chung là điểm vô cực.")
            
        # Thông thường trong ECDH, tọa độ X của điểm S được dùng làm Khóa Đối Xứng (Symmetric Key)
        # Khóa này sẽ được đưa qua một hàm KDF (Key Derivation Function) hoặc Hash để tạo khóa AES.
        # Ở đây ta trả về tọa độ X dưới dạng bytes (32 bytes cho secp256k1)
        shared_secret_bytes = shared_point.x.to_bytes(32, byteorder='big')
        return shared_secret_bytes

if __name__ == "__main__":
    print("=== Giao thức Trao đổi khóa Elliptic Curve Diffie-Hellman (ECDH) ===\n")
    
    ecdh = ECDH(secp256k1)
    
    # Kịch bản: Alice và Bob muốn thiết lập một khóa bảo mật chung để nhắn tin (sẽ dùng cho AES sau này).
    
    print("[1] Alice tạo cặp khóa của mình...")
    alice_private, alice_public = ecdh.generate_keypair()
    print(f"    - Alice Private Key: {hex(alice_private)[:15]}... (Chỉ Alice biết)")
    print(f"    - Alice Public Key: ({hex(alice_public.x)[:10]}..., {hex(alice_public.y)[:10]}...) (Gửi cho Bob)\n")
    
    print("[2] Bob tạo cặp khóa của mình...")
    bob_private, bob_public = ecdh.generate_keypair()
    print(f"    - Bob Private Key: {hex(bob_private)[:15]}... (Chỉ Bob biết)")
    print(f"    - Bob Public Key: ({hex(bob_public.x)[:10]}..., {hex(bob_public.y)[:10]}...) (Gửi cho Alice)\n")
    
    # --- Trao đổi trên kênh không an toàn ---
    # Alice nhận bob_public, Bob nhận alice_public
    
    print("[3] Hai bên độc lập tính toán Khóa Bí Mật Chung (Shared Secret)...")
    
    # Alice dùng Private Key của mình nhân với Public Key của Bob
    alice_shared_secret = ecdh.compute_shared_secret(alice_private, bob_public)
    print(f"    -> Alice tính được Shared Key: {alice_shared_secret.hex()}")
    
    # Bob dùng Private Key của mình nhân với Public Key của Alice
    bob_shared_secret = ecdh.compute_shared_secret(bob_private, alice_public)
    print(f"    -> Bob tính được Shared Key:   {bob_shared_secret.hex()}\n")
    
    # Kiểm tra xem khóa có khớp nhau không
    if alice_shared_secret == bob_shared_secret:
        print("=> THÀNH CÔNG! Alice và Bob đã tính ra cùng một khóa bí mật chung giống hệt nhau.")
        print("=> Kẻ tấn công trên mạng dù có bắt được Public Key của cả hai cũng không thể tính ra khóa này!")
    else:
        print("=> THẤT BẠI! Khóa không khớp.")
