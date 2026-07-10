# Các hàm toán học nền tảng cho Elliptic Curve Cryptography (ECC)
# Phương trình đường cong: y^2 = x^3 + a*x + b (mod p)

def mod_inverse(k, p):
    """
    Tìm nghịch đảo modulo của k trong trường GF(p) bằng thuật toán Euclid mở rộng.
    Trả về x sao cho (k * x) % p == 1
    """
    if k == 0:
        raise ZeroDivisionError('Không tồn tại nghịch đảo cho 0.')

    if k < 0:
        return p - mod_inverse(-k, p)

    # Thuật toán Euclid mở rộng
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    # Nếu k và p không nguyên tố cùng nhau thì không có nghịch đảo (trong trường hợp p là số nguyên tố thì không xảy ra)
    if old_r != 1:
        raise ValueError('Không tồn tại nghịch đảo modulo.')

    return old_s % p

class Point:
    """Đại diện cho một điểm trên đường cong Elliptic."""
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinity(self):
        """Kiểm tra xem đây có phải là Điểm Vô Cực (Point at Infinity) không."""
        return self.x is None and self.y is None

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y

    def __str__(self):
        if self.is_infinity():
            return "Điểm Vô Cực (O)"
        return f"({self.x}, {self.y})"


class EllipticCurve:
    """Đại diện cho một Đường cong Elliptic y^2 = x^3 + a*x + b (mod p)"""
    def __init__(self, a, b, p, g_x, g_y, n):
        self.a = a
        self.b = b
        self.p = p
        self.G = Point(g_x, g_y) # Điểm cơ sở (Base point / Generator)
        self.n = n # Bậc của điểm cơ sở (Order)

    def is_on_curve(self, point):
        """Kiểm tra xem một điểm có nằm trên đường cong hay không."""
        if point.is_infinity():
            return True
        left = (point.y ** 2) % self.p
        right = (point.x ** 3 + self.a * point.x + self.b) % self.p
        return left == right

    def add_points(self, P, Q):
        """Phép cộng hai điểm P và Q trên đường cong."""
        # 1. Nếu P là vô cực thì P + Q = Q
        if P.is_infinity():
            return Q
        # 2. Nếu Q là vô cực thì P + Q = P
        if Q.is_infinity():
            return P

        # 3. Nếu P = -Q thì P + Q = Điểm Vô Cực
        if P.x == Q.x and P.y == (-Q.y % self.p):
            return Point(None, None)

        # 4. Tính độ dốc (lamda)
        if P == Q:
            # Point Doubling (Nhân đôi điểm P)
            # lamda = (3 * x^2 + a) / (2 * y) (mod p)
            if P.y == 0:
                return Point(None, None)
            num = (3 * (P.x ** 2) + self.a) % self.p
            den = (2 * P.y) % self.p
        else:
            # Point Addition (Cộng 2 điểm khác nhau)
            # lamda = (y2 - y1) / (x2 - x1) (mod p)
            num = (Q.y - P.y) % self.p
            den = (Q.x - P.x) % self.p

        lamda = (num * mod_inverse(den, self.p)) % self.p

        # Tính tọa độ điểm R = P + Q
        # x3 = lamda^2 - x1 - x2 (mod p)
        x_r = (lamda ** 2 - P.x - Q.x) % self.p
        # y3 = lamda * (x1 - x3) - y1 (mod p)
        y_r = (lamda * (P.x - x_r) - P.y) % self.p

        return Point(x_r, y_r)

    def multiply_point(self, k, P):
        """Phép nhân vô hướng k * P bằng thuật toán Double-and-Add (O(log k))"""
        R = Point(None, None) # Khởi tạo R là điểm vô cực
        Q = P

        # Lặp qua từng bit của k (từ LSB đến MSB)
        while k > 0:
            if k % 2 == 1:
                R = self.add_points(R, Q)
            Q = self.add_points(Q, Q)
            k //= 2

        return R

    def subtract_points(self, P, Q):
        """Phép trừ hai điểm P - Q. Bản chất là P + (-Q)"""
        if Q.is_infinity():
            return P
        neg_Q = Point(Q.x, (-Q.y) % self.p)
        return self.add_points(P, neg_Q)

# ==============================================================================
# CẤU HÌNH ĐƯỜNG CONG TIÊU CHUẨN SECP256K1 (Dùng trong Bitcoin)
# Phương trình: y^2 = x^3 + 7 (mod p)
# Tức là a = 0, b = 7
# ==============================================================================
SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
SECP256K1_G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Khởi tạo đối tượng đường cong chuẩn
secp256k1 = EllipticCurve(
    a=SECP256K1_A,
    b=SECP256K1_B,
    p=SECP256K1_P,
    g_x=SECP256K1_G_X,
    g_y=SECP256K1_G_Y,
    n=SECP256K1_N
)
