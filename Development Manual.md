# S-AES 开发手册

本文档说明项目的架构，以及 `SAESCore`、`MultiSAES`、`CBCMode` 三个核心类的接口。这些类不依赖任何界面代码，可以直接拿去在命令行程序、网络程序或其他界面里调用。

## 目录

- [1. 架构总览](#1-架构总览)
- [2. 约定](#2-约定)
- [3. SAESCore：基础算法](#3-saescore基础算法)
- [4. MultiSAES：多重加密与中间相遇攻击](#4-multisaes多重加密与中间相遇攻击)
- [5. CBCMode：CBC 工作模式](#5-cbcmodecbc-工作模式)
- [6. 界面类](#6-界面类)
- [7. 集成示例](#7-集成示例)
- [8. 扩展指南](#8-扩展指南)
- [9. 已知限制](#9-已知限制)
- [附录 A：测试向量](#附录-a测试向量)
- [附录 B：密钥扩展验证](#附录-b密钥扩展验证)

---

## 1. 架构总览

```text
                ┌───────────────────────────────┐
                │ SAESGuiApp（窗口 + main）      │
                │   └─ SAESMainPanel（6 个标签页）│
                └───────┬───────────────────────┘
                        │ 只调用，不含算法
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
   SAESCore  ◄──── MultiSAES        CBCMode
 （分组加解密）   （双重/三重/MITM）   （CBC/篡改）
```

| 类              | 职责                                                                           | 是否依赖界面 |
| --------------- | ------------------------------------------------------------------------------ | ------------ |
| `SAESCore`      | GF(2⁴) 运算、四个变换、密钥扩展、分组加解密、字节 / 字符串加解密、位串解析工具 | 否           |
| `MultiSAES`     | 双重加密、三重加密（32 / 48 位密钥）、中间相遇攻击                             | 否           |
| `CBCMode`       | CBC 加解密、初始向量生成、密文篡改、十六进制格式化                             | 否           |
| `SAESMainPanel` | 界面面板：读输入、调用上面三个类、显示结果与日志                               | 是           |
| `SAESGuiApp`    | 创建 `JFrame`，放入 `SAESMainPanel`                                            | 是           |
| `FontProvider`  | 探测系统字体，提供界面字体常量                                                 | 是           |
| `SAESSelfTest`  | 命令行自检，输出测试数据                                                       | 否           |

分层的好处：算法类可以单独测试，界面类换成别的 UI 框架时不用动算法。

---

## 2. 约定

### 2.1 数据表示

| 数据                  | Java 类型             | 说明                                              |
| --------------------- | --------------------- | ------------------------------------------------- |
| 16 位分组 / 16 位密钥 | `int`（低 16 位有效） | 如 `0x6F6B`                                       |
| 32 位密钥             | `long`                | 高 16 位是 K1，低 16 位是 K2                      |
| 48 位密钥             | `long`                | K1、K2、K3                                        |
| 位串接口              | `String`              | 如 `"0110111101101011"`，高位在前；解析时忽略空白 |

### 2.2 状态矩阵

16 位分组按列排入 2×2 半字节矩阵（与教材图 D.2 一致）：

```text
bit15..12  bit7..4         S00  S01
bit11..8   bit3..0    =    S10  S11
```

### 2.3 有限域

GF(2⁴)，模多项式 `x⁴ + x + 1`（0x13）。例：`4•C = 5`，`9•4 = 2`。

### 2.4 异常

输入格式不对（位数不对、含非 0/1 字符、非 ASCII 字符等）一律抛出 `IllegalArgumentException`，消息是可以直接展示给用户的中文说明。

---

## 3. SAESCore：基础算法

包：`saes`；`public final class SAESCore`，全部为静态方法。

### 3.1 分组加解密

#### `encryptBlock`

```java
public static int encryptBlock(int plain, int key)
public static int encryptBlock(int plain, int key, ProcessListener listener)
```

加密一个 16 位分组。`listener` 可为 `null`；不为空时，每个中间步骤都会回调（见 [3.5](#35-过程回调-processlistener)）。

```java
int c = SAESCore.encryptBlock(0x6F6B, 0xA73B);   // 0x0738
```

#### `decryptBlock`

```java
public static int decryptBlock(int cipher, int key)
public static int decryptBlock(int cipher, int key, ProcessListener listener)
```

解密一个 16 位分组，顺序为 `AK(K2) → ISR → INS → AK(K1) → IMC → ISR → INS → AK(K0)`。

#### `encrypt` / `decrypt`（位串接口）

```java
public static String encrypt(String plainBits, String keyBits)
public static String decrypt(String cipherBits, String keyBits)
```

输入输出均为 16 位二进制串。位数不对或含非 0/1 字符时抛 `IllegalArgumentException`。

```java
SAESCore.encrypt("0110111101101011", "1010011100111011");  // "0000011100111000"
```

### 3.2 字节与字符串加解密

#### `encryptBytes` / `decryptBytes`

```java
public static byte[] encryptBytes(byte[] data, int key, ProcessListener listener)
public static byte[] decryptBytes(byte[] data, int key, ProcessListener listener)
```

按 2 字节分组做 ECB 加解密（高字节在前）。

- 加密：字节数为奇数时末尾补 `0x00`，返回的密文长度恒为偶数
- 解密：密文字节数必须为偶数，否则抛异常；结果去掉末尾一个 `0x00`（补位）
- `listener` 每组回调一次：名称为 `第 N 组`，值为 `输入分组 -> 输出分组`

#### `encryptString` / `decryptString`

```java
public static String encryptString(String message, String keyBits)
public static String decryptString(String cipherMessage, String keyBits)
```

- 明文必须是 ASCII（0~127），否则抛异常并指出第几个字符
- 密文用 ISO-8859-1 字符串表示：每个字符对应一个密文字节（0~255），所以可能包含不可见字符；传输和存储请优先使用十六进制或直接用字节数组

### 3.3 GF(2⁴) 与密钥扩展

```java
public static int gfMultiply(int a, int b)       // GF(2^4) 乘法
public static int[] expandKey(int key)           // 返回 w0..w5（各 8 位）
public static int[] roundKeys(int key)           // 返回 {K0, K1, K2}（各 16 位）
```

```java
SAESCore.expandKey(0x2D55);   // {0x2D, 0x55, 0xBC, 0xE9, 0xA3, 0x4A}，教材 D.3 的例子
```

### 3.4 工具方法

| 方法                                                          | 说明                                                     |
| ------------------------------------------------------------- | -------------------------------------------------------- |
| `int parseBits(String bits, int expectedLength, String name)` | 解析定长二进制串，忽略空白；失败时异常消息以 `name` 开头 |
| `String toBits(long value, int length)`                       | 整数转定长二进制串（高位补 0）                           |
| `String toHex(int block)`                                     | 16 位分组转 4 位大写十六进制                             |
| `int sBox(int nibble)` / `int invSBox(int nibble)`            | 查 S 盒 / 逆 S 盒                                        |
| `byte[] asciiBytes(String text)`                              | 校验 ASCII 并转字节                                      |
| `int[] bytesToBlocks(byte[] data)`                            | 字节转 16 位分组，奇数长度补 `0x00`                      |
| `byte[] blocksToBytes(int[] blocks)`                          | 16 位分组转字节                                          |
| `byte[] stripZeroPad(byte[] data)`                            | 去掉末尾一个 `0x00`                                      |

### 3.5 过程回调 `ProcessListener`

```java
public interface ProcessListener {
    void onStep(String stepName, String value);
}
```

`encryptBlock` 的回调顺序：

| 序号 | `stepName`          |
| ---- | ------------------- |
| 1    | 输入                |
| 2    | 密钥扩展            |
| 3    | 轮密钥              |
| 4    | 第0轮 AK(K0)        |
| 5    | 第1轮 半字节代替 NS |
| 6    | 第1轮 行移位 SR     |
| 7    | 第1轮 列混淆 MC     |
| 8    | 第1轮 AK(K1)        |
| 9    | 第2轮 半字节代替 NS |
| 10   | 第2轮 行移位 SR     |
| 11   | 第2轮 AK(K2)        |
| 12   | 输出                |

`value` 里的状态格式为 `1100 1000 0101 0000 (0xC850)`。界面就是用这个回调把过程写进“运算日志”的：

```java
SAESCore.encryptBlock(0x6F6B, 0xA73B, (name, value) -> System.out.println(name + " : " + value));
```

---

## 4. MultiSAES：多重加密与中间相遇攻击

包：`saes`；`public final class MultiSAES`，全部为静态方法。

### 4.1 双重加密

```java
public static int doubleEncrypt(int plain, long key32)    // C = E(K2, E(K1, P))
public static int doubleDecrypt(int cipher, long key32)   // P = D(K1, D(K2, C))
```

`key32` 的高 16 位是 K1，低 16 位是 K2。

### 4.2 三重加密

```java
public static int tripleEncrypt32(int plain, long key32)   // C = E(K1, D(K2, E(K1, P)))
public static int tripleDecrypt32(int cipher, long key32)
public static int tripleEncrypt48(int plain, long key48)   // C = E(K3, D(K2, E(K1, P)))
public static int tripleDecrypt48(int cipher, long key48)

public static int tripleEncrypt(int plain, long key, TripleMode mode)
public static int tripleDecrypt(int cipher, long key, TripleMode mode)
```

`TripleMode` 有两个取值：`KEY_32`（label 为“三重加密（32 位密钥 K1+K2）”，`keyBits = 32`）、`KEY_48`（`keyBits = 48`）。

> 当 K1 = K2 时，32 位三重模式退化为单重加密 `E(K1, P)`，这是 EDE 结构的特点，单元测试里有验证。

### 4.3 中间相遇攻击

```java
public static MitmResult meetInTheMiddle(int[] plains, int[] ciphers, int maxKeep)
```

| 参数                 | 说明                                |
| -------------------- | ----------------------------------- |
| `plains` / `ciphers` | 已知的明密文对，长度相同，至少 1 组 |
| `maxKeep`            | 最多返回多少个匹配的密钥            |

返回 `MitmResult`：

| 字段                  | 类型         | 说明                                                              |
| --------------------- | ------------ | ----------------------------------------------------------------- |
| `keys`                | `List<Long>` | 与全部明密文对吻合的 32 位密钥（K1<<16 \| K2），最多 `maxKeep` 个 |
| `totalMatched`        | `long`       | 吻合的密钥总数                                                    |
| `firstPairCandidates` | `long`       | 只用第 1 组对时的候选数                                           |
| `elapsedMillis`       | `long`       | 耗时（毫秒）                                                      |

算法：

1. 用第 1 组 `(P0, C0)` 枚举全部 K1，把 `E(K1, P0)` 存入链式哈希表（`head[]` / `next[]` 两个 `int[65536]`）
2. 枚举全部 K2，算 `D(K2, C0)`，在表中查同值的 K1，得到候选
3. 用其余明密文对验证候选，全部吻合才保留

时间约 2 × 2¹⁶ 次分组运算，空间 2 × 65536 个 `int`。

```java
int[] p = {0x1234, 0xABCD, 0x0F0F};
int[] c = new int[3];
for (int i = 0; i < 3; i++) c[i] = MultiSAES.doubleEncrypt(p[i], 0xBEEF1234L);
MultiSAES.MitmResult r = MultiSAES.meetInTheMiddle(p, c, 5);
// r.keys 包含 0xBEEF1234L
```

### 4.4 其他

```java
public static long parseKey(String bits, int expectedBits)   // 解析 32/48 位二进制密钥串
```

---

## 5. CBCMode：CBC 工作模式

包：`saes`；`public final class CBCMode`，全部为静态方法。

```text
加密：C_i = E_K( P_i XOR C_{i-1} )，C_0 = IV
解密：P_i = D_K( C_i ) XOR C_{i-1}
```

### 5.1 初始向量

```java
public static int generateIv()
```

用 `SecureRandom` 生成 16 位 IV。IV 不需要保密，但加解密双方必须一致（通常和密文一起发送）。

### 5.2 分组级接口

```java
public static int[] encryptBlocks(int[] plainBlocks, int key, int iv)
public static int[] decryptBlocks(int[] cipherBlocks, int key, int iv)
```

### 5.3 文本接口

```java
public static int[] encryptText(String text, int key, int iv)
public static String decryptToText(int[] cipherBlocks, int key, int iv)
```

`encryptText` 要求 ASCII，奇数字节末尾补 `0x00`；`decryptToText` 去掉一个末尾 `0x00`，按 ISO-8859-1 还原成字符串（被篡改或密钥错误时，结果里可能出现不可见字符）。

### 5.4 篡改工具

```java
public enum TamperMode { FLIP_BIT, REPLACE, SWAP }
public static int[] tamper(int[] cipherBlocks, int index, TamperMode mode)
```

| 模式       | 作用                                     |
| ---------- | ---------------------------------------- |
| `FLIP_BIT` | 把第 `index` 块（从 0 开始）的最低位取反 |
| `REPLACE`  | 把该块替换为 `0xFFFF`                    |
| `SWAP`     | 该块与下一块互换；最后一块会抛异常       |

返回的是副本，不会修改原数组；块号越界抛 `IllegalArgumentException`。

### 5.5 格式化

```java
public static String formatHex(int[] blocks)   // {0x1A53, 0x94D0} -> "1A53 94D0"
public static int[] parseHex(String hex)       // 反向；长度必须是 4 的倍数个十六进制字符
```

### 5.6 CBC 篡改的传播规律

设篡改了密文块 `C_j`：

- `P_j = D(C_j') ⊕ C_{j-1}`：`C_j` 变了，`D` 的输出基本上是不相关的新值，**整块出错**
- `P_{j+1} = D(C_{j+1}) ⊕ C_j'`：`D(C_{j+1})` 没变，只是异或的“前一块”变了，所以出错的位正好等于对 `C_j` 做的改动（翻转 1 位就只有 1 位出错）
- 其余块不受影响

---

## 6. 界面类

### `SAESMainPanel`

`JPanel` 子类，包含 6 个标签页。可以放进任何 `JFrame` / `JDialog`。

| 方法（私有）                         | 作用                                                         |
| ------------------------------------ | ------------------------------------------------------------ |
| `buildBasicTab()` 等 `buildXxxTab()` | 搭建各标签页                                                 |
| `onBasicEncrypt()` 等 `onXxx()`      | 按钮事件：读输入 → 调用核心类 → 写结果和日志                 |
| `runSafely(Runnable)`                | 统一捕获 `IllegalArgumentException` 并弹出提示               |
| `logStep(name, value)`               | 实现 `ProcessListener`，把过程写进日志（按显示宽度对齐中文） |

中间相遇攻击使用 `SwingWorker` 在后台线程运行，运行期间按钮置灰，避免界面卡住。

### `SAESGuiApp`

```java
public static void main(String[] args)
```

创建窗口、设置图标（读不到 `/icon.png` 就忽略）并显示。

### `FontProvider`

探测系统中真正存在的中英文字体，提供标题 / 正文 / 等宽三套字体族和各层级的字号常量（`appTitle()`、`label()`、`input()`、`log()` 等）。

---

## 7. 集成示例

### 7.1 命令行加解密

```java
public class Demo {
    public static void main(String[] args) {
        int key = 0xA73B;
        int cipher = SAESCore.encryptBlock(0x6F6B, key);
        System.out.printf("C = %s%n", SAESCore.toHex(cipher));                   // 0738
        System.out.printf("P = %s%n", SAESCore.toHex(SAESCore.decryptBlock(cipher, key)));
    }
}
```

### 7.2 加密一个文件（逐 2 字节分组）

```java
byte[] data = java.nio.file.Files.readAllBytes(java.nio.file.Path.of("in.bin"));
byte[] enc = SAESCore.encryptBytes(data, 0xA73B, null);
java.nio.file.Files.write(java.nio.file.Path.of("out.bin"), enc);
```

> 这是 ECB 模式，相同的 2 字节会得到相同的密文。长数据请用 `CBCMode`。

### 7.3 把过程写进自己的日志

```java
StringBuilder log = new StringBuilder();
SAESCore.encryptBlock(0x6F6B, 0xA73B, (name, value) -> log.append(name).append(": ").append(value).append('\n'));
```

### 7.4 CBC 加密、篡改、对比

```java
int key = 0xA73B, iv = CBCMode.generateIv();
int[] c = CBCMode.encryptText("Attack at dawn, CBC demo!", key, iv);
int[] bad = CBCMode.tamper(c, 1, CBCMode.TamperMode.FLIP_BIT);
System.out.println(CBCMode.decryptToText(c, key, iv));
System.out.println(CBCMode.decryptToText(bad, key, iv));
```

### 7.5 与其他组做交叉测试

只需要保证双方在以下几点一致：

1. 16 位分组、16 位密钥，明文高位在前
2. 状态矩阵按列排列（前 8 位是第一列）
3. S 盒、列混淆矩阵 `[1 4; 4 1]`、模多项式 `x⁴+x+1`、RCON(1)=`10000000`、RCON(2)=`00110000`
4. 字符串补位规则、多重加密的密钥顺序

然后用同一个密钥对同一个明文加密，比较密文即可（测试向量见附录 A）。

---

## 8. 扩展指南

### 8.1 换一个 S 盒

修改 `SAESCore` 里的 `S_BOX` 和 `INV_S_BOX` 两个数组即可，注意两者必须互逆。`SAESSelfTest` 里有“求逆 + 仿射变换重新生成 S 盒”和“逆 S 盒与 S 盒互逆”两项检查，改完后先跑自检。

### 8.2 增加新的工作模式（如 CTR、OFB）

参照 `CBCMode` 新建一个类，只用 `SAESCore.encryptBlock` / `decryptBlock` 做底层运算。CTR / OFB 解密也只需要加密函数。

### 8.3 为中间相遇攻击提速

目前是单线程。外层 K2 循环相互独立，可以改成 `IntStream.range(0, 65536).parallel()`，并把计数器换成 `LongAdder`、结果列表换成并发集合。

### 8.4 增加新的界面主题

颜色常量集中在 `SAESMainPanel` 开头（`CREAM_BG`、`GREEN` 等），字体集中在 `FontProvider`。

---

## 9. 已知限制

| 限制                         | 说明                                                                                 |
| ---------------------------- | ------------------------------------------------------------------------------------ |
| S-AES 本身不安全             | 16 位密钥只有 65536 种可能，几乎瞬间就能暴力破解；仅供学习                           |
| 字符串只支持 ASCII           | 非 ASCII 字符会被拒绝；如需中文，应先按 UTF-8 转字节再用 `encryptBytes`              |
| 补位用 `0x00`                | 以 `0x00` 结尾的明文在解密时会被多去掉一个字节；需要严格可逆请改用 PKCS#7 一类的补位 |
| 字符串密文用 ISO-8859-1 表示 | 含不可见字符，不要直接用文本框复制粘贴，请用十六进制                                 |
| 多重加密默认 ECB             | `MultiSAES` 只处理单个 16 位分组                                                     |
| CBC 不防篡改                 | 见 5.6，只会传播错误，不会检测错误                                                   |
| 中间相遇攻击只针对双重加密   | 三重加密需要更大的搜索量                                                             |

---

## 附录 A：测试向量

| 明文                       | 密钥                       | 密文                       |
| -------------------------- | -------------------------- | -------------------------- |
| `0110111101101011`（6F6B） | `1010011100111011`（A73B） | `0000011100111000`（0738） |

## 附录 B：密钥扩展验证

教材 D.3 的例子，密钥 `2D55 = 0010 1101 0101 0101`：

| 字  | 值         |
| --- | ---------- |
| w0  | `00101101` |
| w1  | `01010101` |
| w2  | `10111100` |
| w3  | `11101001` |
| w4  | `10100011` |
| w5  | `01001010` |

密钥 `A73B` 的扩展：w0..w5 = `A7 3B 1C 27 76 51`，即 K0 = `A73B`，K1 = `1C27`，K2 = `7651`。
