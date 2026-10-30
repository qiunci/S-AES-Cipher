package saes;

import java.util.ArrayList;
import java.util.List;

/**
 * 多重加密（第 4 关）：双重加密、三重加密，以及针对双重加密的中间相遇攻击。
 * <p>
 * 密钥约定：32 bit 密钥 = K1(高16位) + K2(低16位)；48 bit 密钥 = K1 + K2 + K3。
 */
public final class MultiSAES {

    private MultiSAES() {}

    /** 三重加密的两种模式 */
    public enum TripleMode {
        /** 32 bit 密钥：C = E_K1( D_K2( E_K1(P) ) ) */
        KEY_32("三重加密（32 位密钥 K1+K2）", 32),
        /** 48 bit 密钥：C = E_K3( D_K2( E_K1(P) ) ) */
        KEY_48("三重加密（48 位密钥 K1+K2+K3）", 48);

        public final String label;
        public final int keyBits;

        TripleMode(String label, int keyBits) {
            this.label = label;
            this.keyBits = keyBits;
        }
    }

    // ==================== 双重加密 ====================

    /** C = E_K2( E_K1(P) )，key32 的高 16 位是 K1，低 16 位是 K2 */
    public static int doubleEncrypt(int plain, long key32) {
        int k1 = (int) ((key32 >> 16) & 0xFFFF);
        int k2 = (int) (key32 & 0xFFFF);
        return SAESCore.encryptBlock(SAESCore.encryptBlock(plain, k1), k2);
    }

    /** P = D_K1( D_K2(C) ) */
    public static int doubleDecrypt(int cipher, long key32) {
        int k1 = (int) ((key32 >> 16) & 0xFFFF);
        int k2 = (int) (key32 & 0xFFFF);
        return SAESCore.decryptBlock(SAESCore.decryptBlock(cipher, k2), k1);
    }

    // ==================== 三重加密（EDE） ====================

    /** 32 位密钥模式：C = E_K1( D_K2( E_K1(P) ) ) */
    public static int tripleEncrypt32(int plain, long key32) {
        int k1 = (int) ((key32 >> 16) & 0xFFFF);
        int k2 = (int) (key32 & 0xFFFF);
        return SAESCore.encryptBlock(SAESCore.decryptBlock(SAESCore.encryptBlock(plain, k1), k2), k1);
    }

    /** 32 位密钥模式解密：P = D_K1( E_K2( D_K1(C) ) ) */
    public static int tripleDecrypt32(int cipher, long key32) {
        int k1 = (int) ((key32 >> 16) & 0xFFFF);
        int k2 = (int) (key32 & 0xFFFF);
        return SAESCore.decryptBlock(SAESCore.encryptBlock(SAESCore.decryptBlock(cipher, k1), k2), k1);
    }

    /** 48 位密钥模式：C = E_K3( D_K2( E_K1(P) ) ) */
    public static int tripleEncrypt48(int plain, long key48) {
        int k1 = (int) ((key48 >> 32) & 0xFFFF);
        int k2 = (int) ((key48 >> 16) & 0xFFFF);
        int k3 = (int) (key48 & 0xFFFF);
        return SAESCore.encryptBlock(SAESCore.decryptBlock(SAESCore.encryptBlock(plain, k1), k2), k3);
    }

    /** 48 位密钥模式解密：P = D_K1( E_K2( D_K3(C) ) ) */
    public static int tripleDecrypt48(int cipher, long key48) {
        int k1 = (int) ((key48 >> 32) & 0xFFFF);
        int k2 = (int) ((key48 >> 16) & 0xFFFF);
        int k3 = (int) (key48 & 0xFFFF);
        return SAESCore.decryptBlock(SAESCore.encryptBlock(SAESCore.decryptBlock(cipher, k3), k2), k1);
    }

    /** 按模式统一调用，供界面使用 */
    public static int tripleEncrypt(int plain, long key, TripleMode mode) {
        return mode == TripleMode.KEY_32 ? tripleEncrypt32(plain, key) : tripleEncrypt48(plain, key);
    }

    public static int tripleDecrypt(int cipher, long key, TripleMode mode) {
        return mode == TripleMode.KEY_32 ? tripleDecrypt32(cipher, key) : tripleDecrypt48(cipher, key);
    }

    // ==================== 中间相遇攻击 ====================

    /** 中间相遇攻击结果 */
    public static final class MitmResult {
        /** 与全部明密文对都吻合的 32 位密钥（K1<<16 | K2），最多保留 maxKeep 个 */
        public final List<Long> keys;
        /** 与全部明密文对都吻合的密钥总数 */
        public final long totalMatched;
        /** 只用第一组明密文对时的候选密钥数（用来展示“多一组对能过滤多少”） */
        public final long firstPairCandidates;
        public final long elapsedMillis;

        MitmResult(List<Long> keys, long totalMatched, long firstPairCandidates, long elapsedMillis) {
            this.keys = keys;
            this.totalMatched = totalMatched;
            this.firstPairCandidates = firstPairCandidates;
            this.elapsedMillis = elapsedMillis;
        }
    }

    /**
     * 对双重加密做中间相遇攻击。
     * <p>
     * 思路：C = E_K2(E_K1(P)) 等价于 E_K1(P) = D_K2(C)。
     *   1. 用第一对 (P0, C0) 枚举全部 K1，把中间值 E_K1(P0) 存进表（65536 项）。
     *   2. 枚举全部 K2，算 D_K2(C0)，到表里找相同中间值，得到候选 (K1, K2)。
     *   3. 用其余明密文对验证候选，全部吻合的才保留。
     * 复杂度约 2 * 2^16 次分组运算，而不是暴力穷举的 2^32 次。
     *
     * @param plains  已知明文（16 bit，至少 1 个）
     * @param ciphers 对应密文，长度与 plains 相同
     * @param maxKeep 最多返回多少个匹配密钥
     */
    public static MitmResult meetInTheMiddle(int[] plains, int[] ciphers, int maxKeep) {
        if (plains.length == 0 || plains.length != ciphers.length) {
            throw new IllegalArgumentException("至少需要一组明密文对，且明文与密文数量必须相同");
        }
        long start = System.nanoTime();

        // 链式哈希表：head[中间值] -> K1，next[K1] -> 同一中间值的下一个 K1
        int[] head = new int[65536];
        int[] next = new int[65536];
        java.util.Arrays.fill(head, -1);
        for (int k1 = 0; k1 < 65536; k1++) {
            int middle = SAESCore.encryptBlock(plains[0], k1);
            next[k1] = head[middle];
            head[middle] = k1;
        }

        List<Long> kept = new ArrayList<>();
        long matched = 0;
        long candidates = 0;
        for (int k2 = 0; k2 < 65536; k2++) {
            int middle = SAESCore.decryptBlock(ciphers[0], k2);
            for (int k1 = head[middle]; k1 != -1; k1 = next[k1]) {
                candidates++;
                if (verifyOtherPairs(plains, ciphers, k1, k2)) {
                    matched++;
                    if (kept.size() < maxKeep) kept.add(((long) k1 << 16) | k2);
                }
            }
        }
        long elapsed = (System.nanoTime() - start) / 1_000_000;
        return new MitmResult(kept, matched, candidates, elapsed);
    }

    private static boolean verifyOtherPairs(int[] plains, int[] ciphers, int k1, int k2) {
        for (int i = 1; i < plains.length; i++) {
            if (SAESCore.encryptBlock(SAESCore.encryptBlock(plains[i], k1), k2) != ciphers[i]) return false;
        }
        return true;
    }

    /** 解析 32/48 位二进制密钥串 */
    public static long parseKey(String bits, int expectedBits) {
        String clean = bits == null ? "" : bits.replaceAll("\\s+", "");
        if (clean.length() != expectedBits) {
            throw new IllegalArgumentException("密钥必须是 " + expectedBits + " 位二进制数，当前为 " + clean.length() + " 位");
        }
        if (!clean.matches("[01]+")) throw new IllegalArgumentException("密钥只能包含 0 和 1");
        return Long.parseLong(clean, 2);
    }
}
