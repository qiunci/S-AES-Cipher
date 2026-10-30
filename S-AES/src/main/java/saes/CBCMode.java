package saes;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * S-AES 的 CBC（密码分组链）工作模式（第 5 关）。
 * <p>
 *   加密：C_i = E_K( P_i XOR C_{i-1} )，C_0 = IV
 *   解密：P_i = D_K( C_i ) XOR C_{i-1}
 * <p>
 * IV 为 16 bit，由加密方随机生成后与密文一起（或事先）告知解密方。
 */
public final class CBCMode {

    private CBCMode() {}

    private static final SecureRandom RANDOM = new SecureRandom();

    /** 篡改方式 */
    public enum TamperMode {
        FLIP_BIT("翻转第 N 块的最低 1 位"),
        REPLACE("把第 N 块替换为固定值 0xFFFF"),
        SWAP("把第 N 块与下一块互换");

        public final String label;

        TamperMode(String label) {
            this.label = label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    /** 用安全随机数生成 16 bit 初始向量 */
    public static int generateIv() {
        return RANDOM.nextInt(65536);
    }

    /** 对分组数组做 CBC 加密 */
    public static int[] encryptBlocks(int[] plainBlocks, int key, int iv) {
        int[] cipher = new int[plainBlocks.length];
        int previous = iv & 0xFFFF;
        for (int i = 0; i < plainBlocks.length; i++) {
            cipher[i] = SAESCore.encryptBlock(plainBlocks[i] ^ previous, key);
            previous = cipher[i];
        }
        return cipher;
    }

    /** 对分组数组做 CBC 解密 */
    public static int[] decryptBlocks(int[] cipherBlocks, int key, int iv) {
        int[] plain = new int[cipherBlocks.length];
        int previous = iv & 0xFFFF;
        for (int i = 0; i < cipherBlocks.length; i++) {
            plain[i] = SAESCore.decryptBlock(cipherBlocks[i], key) ^ previous;
            previous = cipherBlocks[i];
        }
        return plain;
    }

    /** ASCII 字符串 -> CBC 密文分组（奇数字节末尾补 0x00） */
    public static int[] encryptText(String text, int key, int iv) {
        return encryptBlocks(SAESCore.bytesToBlocks(SAESCore.asciiBytes(text)), key, iv);
    }

    /** CBC 密文分组 -> 明文字节（去掉一个不位 0x00），用 ISO-8859-1 还原成字符串 */
    public static String decryptToText(int[] cipherBlocks, int key, int iv) {
        byte[] bytes = SAESCore.stripZeroPad(SAESCore.blocksToBytes(decryptBlocks(cipherBlocks, key, iv)));
        return new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    /**
     * 篡改密文分组并返回副本，不修改原数组。
     *
     * @param index 从 0 开始的块号
     */
    public static int[] tamper(int[] cipherBlocks, int index, TamperMode mode) {
        if (index < 0 || index >= cipherBlocks.length) {
            throw new IllegalArgumentException("块号超出范围，共 " + cipherBlocks.length + " 块");
        }
        int[] copy = Arrays.copyOf(cipherBlocks, cipherBlocks.length);
        switch (mode) {
            case FLIP_BIT -> copy[index] ^= 0x0001;
            case REPLACE -> copy[index] = 0xFFFF;
            case SWAP -> {
                if (index + 1 >= copy.length) {
                    throw new IllegalArgumentException("最后一块没有“下一块”可以互换");
                }
                int tmp = copy[index];
                copy[index] = copy[index + 1];
                copy[index + 1] = tmp;
            }
        }
        return copy;
    }

    /** 把分组数组格式化为 "A1B2 C3D4 ..." */
    public static String formatHex(int[] blocks) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < blocks.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(SAESCore.toHex(blocks[i]));
        }
        return sb.toString();
    }

    /** 解析 "A1B2 C3D4 ..."（空白可有可无，必须是 4 的倍数个十六进制字符） */
    public static int[] parseHex(String hex) {
        String clean = hex.replaceAll("\\s+", "");
        if (clean.isEmpty() || clean.length() % 4 != 0 || !clean.matches("[0-9A-Fa-f]+")) {
            throw new IllegalArgumentException("密文必须是 4 的倍数个十六进制字符（每 4 位一个分组）");
        }
        int[] blocks = new int[clean.length() / 4];
        for (int i = 0; i < blocks.length; i++) {
            blocks[i] = Integer.parseInt(clean.substring(4 * i, 4 * i + 4), 16);
        }
        return blocks;
    }
}
