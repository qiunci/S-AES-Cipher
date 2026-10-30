package saes;

/**
 * S-AES（Simplified AES）核心算法，依据《密码编码学与网络安全（第8版）》附录 D 实现。
 * <p>
 * 数据约定：
 *   - 分组 16 bit、密钥 16 bit，内部用 int（低 16 位有效）表示，对外同时提供 "0101..." 位串接口。
 *   - 状态矩阵按列排列：block = S00 S10 S01 S11（每个半字节 4 bit，高位在前）。
 *   - 有限域 GF(2^4) 的模多项式为 x^4 + x + 1。
 * <p>
 * 加密：AK(K2) ∘ SR ∘ NS ∘ AK(K1) ∘ MC ∘ SR ∘ NS ∘ AK(K0)
 * 解密：AK(K0) ∘ INS ∘ ISR ∘ IMC ∘ AK(K1) ∘ INS ∘ ISR ∘ AK(K2)
 */
public final class SAESCore {

    private SAESCore() {}

    /** 教材表 D.1(a)：S 盒，下标 = 行(高2位)*4 + 列(低2位) */
    private static final int[] S_BOX = {
            0x9, 0x4, 0xA, 0xB,
            0xD, 0x1, 0x8, 0x5,
            0x6, 0x2, 0x0, 0x3,
            0xC, 0xE, 0xF, 0x7};

    /** 教材表 D.1(b)：逆 S 盒 */
    private static final int[] INV_S_BOX = {
            0xA, 0x5, 0x9, 0xB,
            0x1, 0x7, 0x8, 0xF,
            0x6, 0x0, 0x2, 0x3,
            0xC, 0x4, 0xD, 0xE};

    /** 列混淆矩阵 [1 4; 4 1] 与其逆矩阵 [9 2; 2 9] 的两个系数 */
    private static final int[] MC_COEF = {1, 4};
    private static final int[] IMC_COEF = {9, 2};

    /** 轮常数 RCON(1)=1000 0000，RCON(2)=0011 0000 */
    private static final int[] RCON = {0x80, 0x30};

    /** 过程回调：用于把每一步的中间结果交给界面或日志 */
    public interface ProcessListener {
        void onStep(String stepName, String value);
    }

    // ==================== GF(2^4) 运算 ====================

    /** GF(2^4) 乘法，模 x^4 + x + 1（0x13）。例：4•C = 5，9•4 = 2 */
    public static int gfMultiply(int a, int b) {
        int result = 0;
        a &= 0xF;
        b &= 0xF;
        for (int i = 0; i < 4; i++) {
            if ((b & 1) != 0) result ^= a;
            boolean overflow = (a & 0x8) != 0;
            a = (a << 1) & 0xF;
            if (overflow) a ^= 0x3; // x^4 = x + 1
            b >>= 1;
        }
        return result;
    }

    // ==================== 四个基本变换（均作用在 2x2 半字节状态上） ====================

    /** 半字节代替 NS / INS */
    private static void substituteNibbles(int[][] s, int[] box) {
        for (int r = 0; r < 2; r++)
            for (int c = 0; c < 2; c++)
                s[r][c] = box[s[r][c]];
    }

    /** 行移位 SR：第二行循环移 1 个半字节；其逆运算相同，所以 ISR 也调用它 */
    private static void shiftRows(int[][] s) {
        int tmp = s[1][0];
        s[1][0] = s[1][1];
        s[1][1] = tmp;
    }

    /** 列混淆 MC / IMC：对每一列左乘 [m0 m1; m1 m0] */
    private static void mixColumns(int[][] s, int[] coef) {
        for (int c = 0; c < 2; c++) {
            int top = s[0][c];
            int bottom = s[1][c];
            s[0][c] = gfMultiply(coef[0], top) ^ gfMultiply(coef[1], bottom);
            s[1][c] = gfMultiply(coef[1], top) ^ gfMultiply(coef[0], bottom);
        }
    }

    /** 轮密钥加 AK：16 位状态与 16 位轮密钥逐位异或 */
    private static void addRoundKey(int[][] s, int roundKey) {
        int[][] k = toState(roundKey);
        for (int r = 0; r < 2; r++)
            for (int c = 0; c < 2; c++)
                s[r][c] ^= k[r][c];
    }

    // ==================== 状态矩阵与分组互转 ====================

    /** 16 bit 分组 -> 2x2 状态：S00=bit15..12，S10=bit11..8，S01=bit7..4，S11=bit3..0 */
    static int[][] toState(int block) {
        int[][] s = new int[2][2];
        s[0][0] = (block >> 12) & 0xF;
        s[1][0] = (block >> 8) & 0xF;
        s[0][1] = (block >> 4) & 0xF;
        s[1][1] = block & 0xF;
        return s;
    }

    static int fromState(int[][] s) {
        return (s[0][0] << 12) | (s[1][0] << 8) | (s[0][1] << 4) | s[1][1];
    }

    // ==================== 密钥扩展 ====================

    /** g 函数：RotNib -> SubNib -> 异或 RCON（对 8 位字操作） */
    private static int gFunction(int word, int rcon) {
        int rotated = ((word & 0xF) << 4) | ((word >> 4) & 0xF);
        int substituted = (S_BOX[(rotated >> 4) & 0xF] << 4) | S_BOX[rotated & 0xF];
        return substituted ^ rcon;
    }

    /**
     * 密钥扩展：16 位密钥 w0w1 -> w0..w5，返回长度为 6 的 8 位字数组。
     * w2 = w0 ^ g(w1)；w3 = w2 ^ w1；w4 = w2 ^ g(w3)；w5 = w4 ^ w3
     */
    public static int[] expandKey(int key) {
        int[] w = new int[6];
        w[0] = (key >> 8) & 0xFF;
        w[1] = key & 0xFF;
        w[2] = w[0] ^ gFunction(w[1], RCON[0]);
        w[3] = w[2] ^ w[1];
        w[4] = w[2] ^ gFunction(w[3], RCON[1]);
        w[5] = w[4] ^ w[3];
        return w;
    }

    /** 三个 16 位轮密钥 K0=w0w1，K1=w2w3，K2=w4w5 */
    public static int[] roundKeys(int key) {
        int[] w = expandKey(key);
        return new int[]{(w[0] << 8) | w[1], (w[2] << 8) | w[3], (w[4] << 8) | w[5]};
    }

    // ==================== 分组加解密 ====================

    public static int encryptBlock(int plain, int key) {
        return encryptBlock(plain, key, null);
    }

    public static int decryptBlock(int cipher, int key) {
        return decryptBlock(cipher, key, null);
    }

    /** 加密一个 16 bit 分组，listener 可为 null */
    public static int encryptBlock(int plain, int key, ProcessListener listener) {
        plain &= 0xFFFF;
        key &= 0xFFFF;
        int[] rk = roundKeys(key);
        note(listener, "输入", "明文 P = " + fmt(plain) + "，密钥 K = " + fmt(key));
        if (listener != null) {
            int[] w = expandKey(key);
            note(listener, "密钥扩展", "w0..w5 = " + hex8(w[0]) + " " + hex8(w[1]) + " " + hex8(w[2])
                    + " " + hex8(w[3]) + " " + hex8(w[4]) + " " + hex8(w[5]));
            note(listener, "轮密钥", "K0 = " + fmt(rk[0]) + "，K1 = " + fmt(rk[1]) + "，K2 = " + fmt(rk[2]));
        }

        int[][] s = toState(plain);
        addRoundKey(s, rk[0]);
        note(listener, "第0轮 AK(K0)", fmt(fromState(s)));

        substituteNibbles(s, S_BOX);
        note(listener, "第1轮 半字节代替 NS", fmt(fromState(s)));
        shiftRows(s);
        note(listener, "第1轮 行移位 SR", fmt(fromState(s)));
        mixColumns(s, MC_COEF);
        note(listener, "第1轮 列混淆 MC", fmt(fromState(s)));
        addRoundKey(s, rk[1]);
        note(listener, "第1轮 AK(K1)", fmt(fromState(s)));

        substituteNibbles(s, S_BOX);
        note(listener, "第2轮 半字节代替 NS", fmt(fromState(s)));
        shiftRows(s);
        note(listener, "第2轮 行移位 SR", fmt(fromState(s)));
        addRoundKey(s, rk[2]);
        int cipher = fromState(s);
        note(listener, "第2轮 AK(K2)", fmt(cipher));
        note(listener, "输出", "密文 C = " + fmt(cipher));
        return cipher;
    }

    /** 解密一个 16 bit 分组，listener 可为 null */
    public static int decryptBlock(int cipher, int key, ProcessListener listener) {
        cipher &= 0xFFFF;
        key &= 0xFFFF;
        int[] rk = roundKeys(key);
        note(listener, "输入", "密文 C = " + fmt(cipher) + "，密钥 K = " + fmt(key));
        note(listener, "轮密钥", "K0 = " + fmt(rk[0]) + "，K1 = " + fmt(rk[1]) + "，K2 = " + fmt(rk[2]));

        int[][] s = toState(cipher);
        addRoundKey(s, rk[2]);
        note(listener, "第2轮逆 AK(K2)", fmt(fromState(s)));
        shiftRows(s);
        note(listener, "第2轮逆 行移位 ISR", fmt(fromState(s)));
        substituteNibbles(s, INV_S_BOX);
        note(listener, "第2轮逆 半字节代替 INS", fmt(fromState(s)));

        addRoundKey(s, rk[1]);
        note(listener, "第1轮逆 AK(K1)", fmt(fromState(s)));
        mixColumns(s, IMC_COEF);
        note(listener, "第1轮逆 列混淆 IMC", fmt(fromState(s)));
        shiftRows(s);
        note(listener, "第1轮逆 行移位 ISR", fmt(fromState(s)));
        substituteNibbles(s, INV_S_BOX);
        note(listener, "第1轮逆 半字节代替 INS", fmt(fromState(s)));

        addRoundKey(s, rk[0]);
        int plain = fromState(s);
        note(listener, "第0轮逆 AK(K0)", fmt(plain));
        note(listener, "输出", "明文 P = " + fmt(plain));
        return plain;
    }

    // ==================== 位串接口（供界面直接使用） ====================

    /** 16 位二进制串加密，返回 16 位二进制串 */
    public static String encrypt(String plainBits, String keyBits) {
        return toBits(encryptBlock(parseBits(plainBits, 16, "明文"), parseBits(keyBits, 16, "密钥")), 16);
    }

    /** 16 位二进制串解密，返回 16 位二进制串 */
    public static String decrypt(String cipherBits, String keyBits) {
        return toBits(decryptBlock(parseBits(cipherBits, 16, "密文"), parseBits(keyBits, 16, "密钥")), 16);
    }

    // ==================== 字节 / 字符串加解密（第 3 关） ====================

    /**
     * 对字节数组按 2 字节分组做 ECB 加密。长度为奇数时末尾补一个 0x00。
     * 返回的密文长度恒为偶数。
     */
    public static byte[] encryptBytes(byte[] data, int key, ProcessListener listener) {
        int[] blocks = bytesToBlocks(data);
        byte[] out = new byte[blocks.length * 2];
        for (int i = 0; i < blocks.length; i++) {
            int c = encryptBlock(blocks[i], key, null);
            note(listener, "第 " + (i + 1) + " 组", fmt(blocks[i]) + " -> " + fmt(c));
            out[2 * i] = (byte) (c >> 8);
            out[2 * i + 1] = (byte) c;
        }
        return out;
    }

    /** ECB 解密；密文长度必须为偶数。若明文末尾是补位的 0x00 则去掉一个。 */
    public static byte[] decryptBytes(byte[] data, int key, ProcessListener listener) {
        if (data.length % 2 != 0) throw new IllegalArgumentException("密文字节数必须是 2 的倍数（每组 2 字节）");
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length / 2; i++) {
            int c = ((data[2 * i] & 0xFF) << 8) | (data[2 * i + 1] & 0xFF);
            int p = decryptBlock(c, key, null);
            note(listener, "第 " + (i + 1) + " 组", fmt(c) + " -> " + fmt(p));
            out[2 * i] = (byte) (p >> 8);
            out[2 * i + 1] = (byte) p;
        }
        return stripZeroPad(out);
    }

    /** ASCII 字符串加密，返回 ISO-8859-1 字符串（每个字符对应一个密文字节，可能含不可见字符） */
    public static String encryptString(String message, String keyBits) {
        return new String(encryptBytes(asciiBytes(message), parseBits(keyBits, 16, "密钥"), null),
                java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    /** encryptString 的逆运算 */
    public static String decryptString(String cipherMessage, String keyBits) {
        byte[] raw = cipherMessage.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        return new String(decryptBytes(raw, parseBits(keyBits, 16, "密钥"), null),
                java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    /** 把明文限制为 ASCII（0~127）并转成字节 */
    public static byte[] asciiBytes(String text) {
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) > 127) {
                throw new IllegalArgumentException("第 " + (i + 1) + " 个字符不是 ASCII 字符：" + text.charAt(i));
            }
        }
        return text.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    /** 字节 -> 16 bit 分组（奇数长度末尾补 0x00） */
    public static int[] bytesToBlocks(byte[] data) {
        int[] blocks = new int[(data.length + 1) / 2];
        for (int i = 0; i < blocks.length; i++) {
            int high = data[2 * i] & 0xFF;
            int low = (2 * i + 1 < data.length) ? data[2 * i + 1] & 0xFF : 0;
            blocks[i] = (high << 8) | low;
        }
        return blocks;
    }

    public static byte[] blocksToBytes(int[] blocks) {
        byte[] out = new byte[blocks.length * 2];
        for (int i = 0; i < blocks.length; i++) {
            out[2 * i] = (byte) (blocks[i] >> 8);
            out[2 * i + 1] = (byte) blocks[i];
        }
        return out;
    }

    /** 去掉末尾一个补位用的 0x00 */
    public static byte[] stripZeroPad(byte[] data) {
        if (data.length > 0 && data[data.length - 1] == 0) {
            return java.util.Arrays.copyOf(data, data.length - 1);
        }
        return data;
    }

    // ==================== 工具方法 ====================

    /** 校验并解析定长二进制串（允许含空格），失败抛出带中文说明的异常 */
    public static int parseBits(String bits, int expectedLength, String name) {
        String clean = bits == null ? "" : bits.replaceAll("\\s+", "");
        if (clean.length() != expectedLength) {
            throw new IllegalArgumentException(name + "必须是 " + expectedLength + " 位二进制数，当前为 " + clean.length() + " 位");
        }
        if (!clean.matches("[01]+")) {
            throw new IllegalArgumentException(name + "只能包含 0 和 1");
        }
        return (int) Long.parseLong(clean, 2);
    }

    /** 整数 -> 定长二进制串 */
    public static String toBits(long value, int length) {
        String s = Long.toBinaryString(value);
        return "0".repeat(Math.max(0, length - s.length())) + s;
    }

    public static String toHex(int block) {
        return String.format("%04X", block & 0xFFFF);
    }

    /** 半字节代替用到的 S 盒查询，测试用 */
    public static int sBox(int nibble) { return S_BOX[nibble & 0xF]; }

    public static int invSBox(int nibble) { return INV_S_BOX[nibble & 0xF]; }

    private static String fmt(int block) {
        String bits = toBits(block, 16);
        return bits.substring(0, 4) + " " + bits.substring(4, 8) + " " + bits.substring(8, 12) + " "
                + bits.substring(12) + " (0x" + toHex(block) + ")";
    }

    private static String hex8(int v) {
        return String.format("%02X", v & 0xFF);
    }

    private static void note(ProcessListener l, String name, String value) {
        if (l != null) l.onStep(name, value);
    }
}
