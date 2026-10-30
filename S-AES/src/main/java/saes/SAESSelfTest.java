package saes;

import java.util.Random;

/**
 * 命令行自检：用教材附录 D 的例子核对算法，并输出可写进测试报告的数据。
 * 运行：java -cp out saes.SAESSelfTest
 */
public final class SAESSelfTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        checkGf();
        checkSBoxGeneration();
        checkKeyExpansion();
        checkTransformExamples();

        checkVectors();
        checkExhaustiveRoundTrip();

        checkStrings();

        checkMultiple();
        checkMitm();

        checkCbc();

        if (failed > 0) System.exit(1);
    }

    // ---------- 第 1 关 ----------

    private static void checkGf() {
        check("GF 乘法 4•C = 5", SAESCore.gfMultiply(0x4, 0xC) == 0x5);
        check("GF 乘法 9•4 = 2", SAESCore.gfMultiply(0x9, 0x4) == 0x2);
        // 逆列混淆矩阵证明：9 + 2•4 = 1，9•4 + 2 = 0
        check("9 ⊕ 2•4 = 1", (0x9 ^ SAESCore.gfMultiply(2, 4)) == 1);
        check("9•4 ⊕ 2 = 0", (SAESCore.gfMultiply(9, 4) ^ 2) == 0);
    }

    /** 按教材 D.4 的方法（GF 求逆 + 仿射变换）重新生成 S 盒，与表 D.1 对比 */
    private static void checkSBoxGeneration() {
        boolean allMatch = true;
        for (int x = 0; x < 16; x++) {
            int inv = 0;
            if (x != 0) {
                for (int y = 1; y < 16; y++) if (SAESCore.gfMultiply(x, y) == 1) inv = y;
            }
            int b0 = (inv >> 3) & 1, b1 = (inv >> 2) & 1, b2 = (inv >> 1) & 1, b3 = inv & 1;
            int n0 = b0 ^ b2 ^ b3 ^ 1;
            int n1 = b0 ^ b1 ^ b3;
            int n2 = b0 ^ b1 ^ b2;
            int n3 = b1 ^ b2 ^ b3 ^ 1;
            int generated = (n0 << 3) | (n1 << 2) | (n2 << 1) | n3;
            if (generated != SAESCore.sBox(x)) allMatch = false;
        }
        check("S 盒与“求逆+仿射变换”重新生成的结果一致", allMatch);
        boolean inverseOk = true;
        for (int x = 0; x < 16; x++)
            if (SAESCore.invSBox(SAESCore.sBox(x)) != x) {
                inverseOk = false;
                break;
            }
        check("逆 S 盒与 S 盒互逆", inverseOk);
    }

    private static void checkKeyExpansion() {
        int[] w = SAESCore.expandKey(0x2D55);
        check("密钥扩展 w2 = 10111100", w[2] == 0b10111100);
        check("密钥扩展 w3 = 11101001", w[3] == 0b11101001);
        check("密钥扩展 w4 = 10100011", w[4] == 0b10100011);
        check("密钥扩展 w5 = 01001010", w[5] == 0b01001010);
    }

    private static void checkTransformExamples() {
        // 半字节代替例子：8 1 / A C -> 6 4 / 0 C
        check("半字节代替 8→6, 1→4, A→0, C→C",
                SAESCore.sBox(0x8) == 0x6 && SAESCore.sBox(0x1) == 0x4
                        && SAESCore.sBox(0xA) == 0x0 && SAESCore.sBox(0xC) == 0xC);
        // 列混淆例子：[1 4;4 1] x [6 4;C 0] = [3 4;7 3]
        int s00 = 0x6, s10 = 0xC, s01 = 0x4, s11 = 0x0;
        int r00 = s00 ^ SAESCore.gfMultiply(4, s10);
        int r10 = SAESCore.gfMultiply(4, s00) ^ s10;
        int r01 = s01 ^ SAESCore.gfMultiply(4, s11);
        int r11 = SAESCore.gfMultiply(4, s01) ^ s11;
        check("列混淆例子 -> 3 4 / 7 3", r00 == 3 && r01 == 4 && r10 == 7 && r11 == 3);
    }

    // ---------- 第 1/2 关 ----------

    private static void checkVectors() {
        String[][] vectors = {
                // 明文, 密钥
                {"0110111101101011", "1010011100111011"},
                {"0000000000000000", "0000000000000000"},
                {"1111111111111111", "1111111111111111"},
                {"1010101010101010", "0101010101010101"},
                {"0001001000110100", "0010110101010101"},
        };
        System.out.println("  明文 / 密钥 / 密文（二进制）：");
        for (String[] v : vectors) {
            String c = SAESCore.encrypt(v[0], v[1]);
            String p = SAESCore.decrypt(c, v[1]);
            check("解密还原 " + v[0], p.equals(v[0]));
        }
        check("文献常用向量 6F6B / A73B -> 0738",
                SAESCore.encrypt("0110111101101011", "1010011100111011").equals("0000011100111000"));
    }

    private static void checkExhaustiveRoundTrip() {
        boolean ok = true;
        Random random = new Random(20241028L);
        for (int t = 0; t < 20 && ok; t++) {
            int key = random.nextInt(65536);
            for (int p = 0; p < 65536; p++) {
                if (SAESCore.decryptBlock(SAESCore.encryptBlock(p, key), key) != p) { ok = false; break; }
            }
        }
        check("20 个随机密钥 × 全部 65536 个明文 加密再解密均还原", ok);
        boolean bijection = true;
        boolean[] seen = new boolean[65536];
        for (int p = 0; p < 65536; p++) {
            int c = SAESCore.encryptBlock(p, 0xA73B);
            if (seen[c]) { bijection = false; break; }
            seen[c] = true;
        }
        check("固定密钥下 65536 个明文映射到 65536 个不同密文（一一对应）", bijection);
    }

    // ---------- 第 3 关 ----------

    private static void checkStrings() {
        String key = "1010011100111011";
        String[] messages = {"Hello", "AB", "S-AES test 2026!", "a"};
        for (String m : messages) {
            String c = SAESCore.encryptString(m, key);
            StringBuilder hex = new StringBuilder();
            for (char ch : c.toCharArray()) hex.append(String.format("%02X", (int) ch));
            String back = SAESCore.decryptString(c, key);
            check("字符串往返 \"" + m + "\"", back.equals(m));
        }
        check("偶数长度字符串密文长度 = 明文长度", SAESCore.encryptString("AB", key).length() == 2);
        check("奇数长度字符串补位后密文多 1 字节", SAESCore.encryptString("a", key).length() == 2);
    }

    // ---------- 第 4 关 ----------

    private static void checkMultiple() {
        int p = 0x6F6B;
        long key32 = 0xA73B2D55L;
        long key48 = 0xA73B2D55FACEL;
        int c2 = MultiSAES.doubleEncrypt(p, key32);
        int c3a = MultiSAES.tripleEncrypt32(p, key32);
        int c3b = MultiSAES.tripleEncrypt48(p, key48);
        System.out.println("  P=6F6B  双重(32位 A73B2D55) C=" + SAESCore.toHex(c2)
                + "  三重(32位) C=" + SAESCore.toHex(c3a)
                + "  三重(48位 A73B2D55FACE) C=" + SAESCore.toHex(c3b));
        check("双重加密往返", MultiSAES.doubleDecrypt(c2, key32) == p);
        check("三重加密(32位)往返", MultiSAES.tripleDecrypt32(c3a, key32) == p);
        check("三重加密(48位)往返", MultiSAES.tripleDecrypt48(c3b, key48) == p);
        check("K1 = K2 时三重(32位)退化为单重加密",
                MultiSAES.tripleEncrypt32(p, 0xA73BA73BL) == SAESCore.encryptBlock(p, 0xA73B));
    }

    private static void checkMitm() {
        long secret = 0xBEEF1234L;
        int[] plains = {0x1234, 0xABCD, 0x0F0F};
        int[] ciphers = new int[plains.length];
        for (int i = 0; i < plains.length; i++) ciphers[i] = MultiSAES.doubleEncrypt(plains[i], secret);

        MultiSAES.MitmResult one = MultiSAES.meetInTheMiddle(
                new int[]{plains[0]}, new int[]{ciphers[0]}, 5);
        MultiSAES.MitmResult three = MultiSAES.meetInTheMiddle(plains, ciphers, 5);
        System.out.println("  真实密钥 " + Long.toHexString(secret).toUpperCase());
        System.out.println("  1 组明密文对：候选 " + one.firstPairCandidates + "，吻合 " + one.totalMatched
                + "，耗时 " + one.elapsedMillis + " ms");
        System.out.println("  3 组明密文对：候选 " + three.firstPairCandidates + "，吻合 " + three.totalMatched
                + " 个：" + hexList(three.keys) + "，耗时 " + three.elapsedMillis + " ms");
        check("3 组明密文对的结果包含真实密钥", three.keys.contains(secret));
        check("1 组明密文对的候选集远多于 3 组", one.totalMatched > three.totalMatched);
    }

    // ---------- 第 5 关 ----------

    private static void checkCbc() {
        int key = 0xA73B;
        int iv = 0x1A2B;
        String text = "CBC mode test: AAAAAAAAAAAA";
        int[] cipher = CBCMode.encryptText(text, key, iv);
        System.out.println("  IV=" + SAESCore.toHex(iv) + " 明文=\"" + text + "\"");
        System.out.println("  密文 = " + CBCMode.formatHex(cipher));
        check("CBC 往返", CBCMode.decryptToText(cipher, key, iv).equals(text));
        check("CBC 错误 IV 只影响第 1 块",
                !CBCMode.decryptToText(cipher, key, iv ^ 1).equals(text));

        // ECB 与 CBC 对比：相同明文块在 CBC 下得到不同密文
        int[] same = CBCMode.encryptText("AAAAAAAA", key, iv);
        boolean allDifferent = true;
        for (int i = 1; i < same.length; i++)
            if (same[i] == same[i - 1]) {
                allDifferent = false;
                break;
            }
        check("相同明文块在 CBC 下密文不同", allDifferent);

        for (CBCMode.TamperMode mode : CBCMode.TamperMode.values()) {
            int[] tampered = CBCMode.tamper(cipher, 1, mode);
            int[] plainOrig = CBCMode.decryptBlocks(cipher, key, iv);
            int[] plainTamp = CBCMode.decryptBlocks(tampered, key, iv);
            StringBuilder diff = new StringBuilder();
            for (int i = 0; i < plainOrig.length; i++) diff.append(plainOrig[i] == plainTamp[i] ? "." : "X");
            System.out.println("  篡改[" + mode.label + "] 第2块：各块解密是否变化 " + diff);
        }
        // 翻转第 2 块一位：第 2 块整块出错，第 3 块只在对应位出错，其余不变
        int[] flipped = CBCMode.tamper(cipher, 1, CBCMode.TamperMode.FLIP_BIT);
        int[] po = CBCMode.decryptBlocks(cipher, key, iv);
        int[] pt = CBCMode.decryptBlocks(flipped, key, iv);
        check("翻转 C2 的 1 位：P3 恰好在同一位翻转", (po[2] ^ pt[2]) == 0x0001);
        check("翻转 C2 的 1 位：P1 不受影响", po[0] == pt[0]);
        check("翻转 C2 的 1 位：P4 之后不受影响", po[3] == pt[3] && po[4] == pt[4]);
    }

    private static String hexList(java.util.List<Long> keys) {
        StringBuilder sb = new StringBuilder("[");
        for (long k : keys) sb.append(String.format("%08X", k)).append(' ');
        return sb.toString().trim() + "]";
    }

    private static void check(String name, boolean ok) {
        if (ok) passed++; else failed++;
        System.out.println((ok ? "  [通过] " : "  [失败] ") + name);
    }

}
