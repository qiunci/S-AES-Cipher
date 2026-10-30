package saes;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * S-AES 图形界面（Swing）。
 * <p>
 * 标签页：基本加解密 / ASCII 字符串 / 多重加密 / 中间相遇攻击 / CBC 模式 / 运算日志。
 * 界面只负责读取输入、调用 SAESCore / MultiSAES / CBCMode 并显示结果，算法本身不含任何界面代码。
 * 本类是可嵌入任意窗口的主面板；窗口外壳见 SAESGuiApp。
 */
public class SAESMainPanel extends JPanel {

    // ========== 配色：奶白 + 复古绿（与 S-DES 工具保持一致） ==========
    private static final Color CREAM_BG = new Color(0xFAF7F0);
    private static final Color CREAM_CARD = new Color(0xFFFCF6);
    private static final Color GREEN = new Color(0x5B7A5B);
    private static final Color GREEN_DARK = new Color(0x445C44);
    private static final Color GREEN_LIGHT = new Color(0xA8BCA8);
    private static final Color SOFT_LINE = new Color(0xD8D2C4);
    private static final Color GOLD = new Color(0xD4BE8A);
    private static final Color TEXT_MAIN = new Color(0x333333);
    private static final Color TEXT_SUB = new Color(0x7A7A7A);
    private static final Color LOG_BG = new Color(0x2F3D2F);
    private static final Color LOG_FG = new Color(0xDCE4D4);
    private static final Color DIFF_BG = new Color(0xF6D9D0);

    private static final SecureRandom RANDOM = new SecureRandom();

    // ---------- 第 1 关：基本加解密 ----------
    private final JTextField basicKeyField = new JTextField(18);
    private final JTextField basicPlainField = new JTextField(18);
    private final JTextField basicCipherField = new JTextField(18);
    private final JLabel basicHexLabel = new JLabel(" ");

    // ---------- 第 3 关：ASCII 字符串 ----------
    private final JTextField strKeyField = new JTextField(18);
    private final JTextArea strPlainArea = new JTextArea(3, 40);
    private final JTextArea strCipherHexArea = new JTextArea(3, 40);
    private final JTextArea strCipherAsciiArea = new JTextArea(3, 40);

    // ---------- 第 4 关：多重加密 + 中间相遇攻击 ----------
    private final JComboBox<String> multiModeBox = new JComboBox<>(new String[]{
            "双重加密（32 位密钥 K1+K2）",
            MultiSAES.TripleMode.KEY_32.label,
            MultiSAES.TripleMode.KEY_48.label});
    private final JTextField multiKeyField = new JTextField(34);
    private final JTextField multiPlainField = new JTextField(18);
    private final JTextField multiCipherField = new JTextField(18);
    private final JLabel multiKeyHint = new JLabel(" ");
    private final JTextArea mitmPairsArea = new JTextArea(6, 40);
    private final JTextArea mitmResultArea = new JTextArea(8, 40);
    private final JLabel mitmHint = new JLabel(" ");
    private final JButton mitmRunButton = makeButton("开始中间相遇攻击", true);

    // ---------- 第 5 关：CBC ----------
    private final JTextField cbcKeyField = new JTextField(18);
    private final JTextField cbcIvField = new JTextField(18);
    private final JTextArea cbcPlainArea = new JTextArea(2, 30);
    private final JTextArea cbcCipherArea = new JTextArea(2, 30);
    private final JSpinner tamperIndexSpinner = new JSpinner(new SpinnerNumberModel(2, 1, 9999, 1));
    private final JComboBox<CBCMode.TamperMode> tamperModeBox = new JComboBox<>(CBCMode.TamperMode.values());
    private final JTextField cbcOriginalResult = new JTextField();
    private final JTextField cbcTamperedResult = new JTextField();
    private final DefaultTableModel cbcTableModel = new DefaultTableModel(
            new String[]{"块号", "原密文", "篡改后密文", "原明文块", "篡改后明文块", "是否变化"}, 0) {
        @Override
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable cbcTable = new JTable(cbcTableModel);

    // ---------- 日志 ----------
    private final JTextArea logArea = new JTextArea(20, 70);
    private final JLabel statusLabel = new JLabel("就绪");

    static {
        // 标签页配色：选中为奶白卡片色，内容区为奶白背景
        UIManager.put("TabbedPane.selected", CREAM_CARD);
        UIManager.put("TabbedPane.contentAreaColor", CREAM_BG);
        UIManager.put("TabbedPane.background", CREAM_BG);
        UIManager.put("TabbedPane.focus", GREEN_LIGHT);
        UIManager.put("TabbedPane.borderHightlightColor", SOFT_LINE);
        UIManager.put("TabbedPane.darkShadow", SOFT_LINE);
        UIManager.put("TabbedPane.light", SOFT_LINE);
        UIManager.put("TabbedPane.shadow", SOFT_LINE);
    }

    public SAESMainPanel() {
        super(new BorderLayout());
        initUi();
    }

    // ==================== 界面搭建 ====================

    private void initUi() {
        basicKeyField.setText("1010011100111011");
        strKeyField.setText("1010011100111011");
        cbcKeyField.setText("1010011100111011");
        cbcIvField.setText(SAESCore.toBits(CBCMode.generateIv(), 16));
        multiKeyField.setText("10100111001110110010110101010101");
        multiPlainField.setText("0110111101101011");
        mitmPairsArea.setText("");

        setBackground(CREAM_BG);
        add(buildHeader(), BorderLayout.NORTH);

        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(FontProvider.tab());
        tabs.setBackground(CREAM_BG);
        tabs.addTab("  基本加解密  ", buildBasicTab());
        tabs.addTab("  ASCII 字符串  ", buildStringTab());
        tabs.addTab("  多重加密  ", buildMultiTab());
        tabs.addTab("  中间相遇攻击  ", buildMitmTab());
        tabs.addTab("  CBC 模式  ", buildCbcTab());
        tabs.addTab("  运算日志  ", buildLogTab());
        add(tabs, BorderLayout.CENTER);

        statusLabel.setFont(FontProvider.status());
        statusLabel.setForeground(TEXT_SUB);
        statusLabel.setBorder(new EmptyBorder(4, 14, 6, 14));
        add(statusLabel, BorderLayout.SOUTH);
        multiModeBox.addActionListener(e -> updateMultiHint());
        updateMultiHint();
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBackground(CREAM_BG);
        header.setBorder(new EmptyBorder(14, 20, 8, 20));
        JLabel title = new JLabel("S-AES");
        title.setFont(FontProvider.appTitle());
        title.setForeground(GREEN);
        JLabel subtitle = new JLabel("简化 AES");
        subtitle.setFont(FontProvider.appSubtitle());
        subtitle.setForeground(TEXT_SUB);
        header.add(title);
        header.add(subtitle);
        header.add(Box.createVerticalStrut(8));
        JSeparator sep = new JSeparator();
        sep.setForeground(GOLD);
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, 1));
        header.add(sep);
        return header;
    }

    // ---------- 第 1 关 ----------
    private JPanel buildBasicTab() {
        JPanel tab = newTab();
        JPanel card = newCard("16 位二进制数据加解密");
        addRow(card, "密钥 K（16 位）", basicKeyField, makeButton("随机密钥", false, e ->
                basicKeyField.setText(SAESCore.toBits(RANDOM.nextInt(65536), 16))));
        addRow(card, "明文 P（16 位）", basicPlainField);
        addRow(card, "密文 C（16 位）", basicCipherField);
        addRow(card, "十六进制", basicHexLabel);
        JPanel buttons = buttonRow(
                makeButton("加密  P → C", true, e -> onBasicEncrypt()),
                makeButton("解密  C → P", true, e -> onBasicDecrypt()));
        card.add(buttons, gbc(0, 4, 3));
        tab.add(card);
        tab.add(hintLabel("输入均为 0/1 位串，可含空格；每次运算的详细过程见“运算日志”标签页。"));
        return tab;
    }

    // ---------- 第 3 关 ----------
    private JPanel buildStringTab() {
        JPanel tab = newTab();
        JPanel card = newCard("ASCII 字符串加解密（每 2 个字符一组）");
        addRow(card, "密钥 K（16 位）", strKeyField);
        addRow(card, "明文（ASCII）", scroll(strPlainArea));
        addRow(card, "密文（十六进制）", scroll(strCipherHexArea));
        strCipherAsciiArea.setEditable(false);
        addRow(card, "密文（ASCII 显示）", scroll(strCipherAsciiArea));
        card.add(buttonRow(
                makeButton("加密  明文 → 密文", true, e -> onStringEncrypt()),
                makeButton("解密  密文 → 明文", true, e -> onStringDecrypt())), gbc(0, 4, 3));
        tab.add(card);
        tab.add(hintLabel("密文每字节对应一个字符，多数不可见，所以用十六进制传递；解密请把十六进制粘贴到“密文（十六进制）”。"
                + "奇数个字符时末尾补 0x00。"));
        return tab;
    }

    // ---------- 第 4 关：多重加密 ----------
    private JPanel buildMultiTab() {
        JPanel tab = newTab();
        JPanel card = newCard("多重加密（分组仍为 16 位）");
        addRow(card, "加密方式", multiModeBox);
        addRow(card, "密钥", multiKeyField, makeButton("随机密钥", false, e -> {
            int bits = currentKeyBits();
            long max = 1L << bits;
            multiKeyField.setText(SAESCore.toBits(Math.floorMod(RANDOM.nextLong(), max), bits));
        }));
        addRow(card, "", multiKeyHint);
        addRow(card, "明文 P（16 位）", multiPlainField);
        addRow(card, "密文 C（16 位）", multiCipherField);
        card.add(buttonRow(
                makeButton("加密  P → C", true, e -> onMultiEncrypt()),
                makeButton("解密  C → P", true, e -> onMultiDecrypt())), gbc(0, 5, 3));
        tab.add(card);
        tab.add(hintLabel("多重加解密"));
        return tab;
    }

    // ---------- 第 4 关：中间相遇攻击 ----------
    private JPanel buildMitmTab() {
        JPanel tab = newTab();
        JPanel card = newCard("对双重加密的中间相遇攻击");
        mitmResultArea.setEditable(false);
        mitmResultArea.setFont(new Font("Dialog", Font.PLAIN, 14));
        mitmPairsArea.setFont(FontProvider.input());
        addRow(card, "已知明密文对", scroll(mitmPairsArea));
        addRow(card, "", mitmHint);
        addRow(card, "攻击结果", scroll(mitmResultArea));
        mitmRunButton.addActionListener(e -> onMitm());
        card.add(buttonRow(
                makeButton("生成演示数据（随机 32 位密钥）", false, e -> onMitmDemo()),
                mitmRunButton), gbc(0, 3, 3));
        tab.add(card);
        tab.add(hintLabel("每行一组：16 位明文 空格 16 位密文。一组明密文对会留下约 65 000 个候选密钥，"
                + "两三组即可唯一确定。"));
        return tab;
    }

    // ---------- 第 5 关：CBC ----------
    private JPanel buildCbcTab() {
        JPanel tab = newTab();
        JPanel card = newCard("CBC 模式加解密与密文篡改");
        addRow(card, "密钥 K（16 位）", cbcKeyField);
        addRow(card, "初始向量 IV（16 位）", cbcIvField, makeButton("随机 IV", false, e ->
                cbcIvField.setText(SAESCore.toBits(CBCMode.generateIv(), 16))));
        addRow(card, "明文（ASCII）", scroll(cbcPlainArea));
        addRow(card, "密文（十六进制）", scroll(cbcCipherArea));
        card.add(buttonRow(
                makeButton("CBC 加密", true, e -> onCbcEncrypt()),
                makeButton("CBC 解密", true, e -> onCbcDecrypt())), gbc(0, 4, 3));

        JPanel tamper = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        tamper.setOpaque(false);
        tamper.add(makeLabel("篡改第"));
        tamperIndexSpinner.setPreferredSize(new Dimension(70, 28));
        tamper.add(tamperIndexSpinner);
        tamper.add(makeLabel("块："));
        tamper.add(tamperModeBox);
        tamper.add(makeButton("篡改并对比解密", true, e -> onCbcTamper()));
        card.add(tamper, gbc(0, 5, 3));

        cbcOriginalResult.setEditable(false);
        cbcTamperedResult.setEditable(false);
        addRow(card, "原密文解密结果", cbcOriginalResult);
        addRow(card, "篡改后解密结果", cbcTamperedResult);

        cbcTable.setFont(FontProvider.log());
        cbcTable.getTableHeader().setFont(FontProvider.label());
        cbcTable.setRowHeight(24);
        cbcTable.setDefaultRenderer(Object.class, (table, value, selected, focus, row, col) -> {
            JLabel cell = new JLabel(String.valueOf(value), SwingConstants.CENTER);
            cell.setOpaque(true);
            cell.setFont(FontProvider.log());
            boolean changed = "是".equals(table.getValueAt(row, 5));
            cell.setBackground(changed ? DIFF_BG : CREAM_CARD);
            cell.setForeground(TEXT_MAIN);
            return cell;
        });
        JScrollPane tableScroll = new JScrollPane(cbcTable);
        tableScroll.setPreferredSize(new Dimension(560, 140));
        tableScroll.setBorder(new LineBorder(SOFT_LINE));
        GridBagConstraints c = gbc(0, 8, 3);
        c.fill = GridBagConstraints.BOTH;
        card.add(tableScroll, c);

        tab.add(card);
        tab.add(hintLabel("每 2 个 ASCII 字符为一组（奇数个字符末尾补 0x00）。篡改后，被改的那一块整块出错，"
                + "下一块只在被改的位上出错，其余块不受影响。"));
        JScrollPane page = new JScrollPane(tab, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        page.setBorder(null);
        page.getVerticalScrollBar().setUnitIncrement(16);
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.add(page, BorderLayout.CENTER);
        return wrapper;
    }

    // ---------- 日志 ----------
    private JPanel buildLogTab() {
        JPanel tab = new JPanel(new BorderLayout(0, 8));
        tab.setBackground(CREAM_BG);
        tab.setBorder(new EmptyBorder(12, 14, 12, 14));
        logArea.setEditable(false);
        logArea.setFont(FontProvider.log());
        logArea.setBackground(LOG_BG);
        logArea.setForeground(LOG_FG);
        logArea.setCaretColor(LOG_FG);
        logArea.setBorder(new EmptyBorder(8, 10, 8, 10));
        JScrollPane scroll = new JScrollPane(logArea);
        scroll.setBorder(new LineBorder(SOFT_LINE));
        tab.add(scroll, BorderLayout.CENTER);
        tab.add(buttonRow(
                makeButton("复制日志", false, e -> {
                    logArea.selectAll();
                    logArea.copy();
                    logArea.select(0, 0);
                    setStatus("日志已复制到剪贴板");
                }),
                makeButton("清空日志", false, e -> logArea.setText(""))), BorderLayout.SOUTH);
        return tab;
    }

    // ==================== 事件处理 ====================

    private void onBasicEncrypt() {
        runSafely(() -> {
            int key = SAESCore.parseBits(basicKeyField.getText(), 16, "密钥");
            int plain = SAESCore.parseBits(basicPlainField.getText(), 16, "明文");
            logHeader("16 位加密");
            int cipher = SAESCore.encryptBlock(plain, key, this::logStep);
            basicCipherField.setText(SAESCore.toBits(cipher, 16));
            basicHexLabel.setText("P = 0x" + SAESCore.toHex(plain) + "    C = 0x" + SAESCore.toHex(cipher));
            setStatus("加密完成");
        });
    }

    private void onBasicDecrypt() {
        runSafely(() -> {
            int key = SAESCore.parseBits(basicKeyField.getText(), 16, "密钥");
            int cipher = SAESCore.parseBits(basicCipherField.getText(), 16, "密文");
            logHeader("16 位解密");
            int plain = SAESCore.decryptBlock(cipher, key, this::logStep);
            basicPlainField.setText(SAESCore.toBits(plain, 16));
            basicHexLabel.setText("P = 0x" + SAESCore.toHex(plain) + "    C = 0x" + SAESCore.toHex(cipher));
            setStatus("解密完成");
        });
    }

    private void onStringEncrypt() {
        runSafely(() -> {
            int key = SAESCore.parseBits(strKeyField.getText(), 16, "密钥");
            byte[] plain = SAESCore.asciiBytes(strPlainArea.getText());
            if (plain.length == 0) throw new IllegalArgumentException("请输入要加密的明文");
            logHeader("字符串加密（" + plain.length + " 字节，" + (plain.length + 1) / 2 + " 组）");
            byte[] cipher = SAESCore.encryptBytes(plain, key, this::logStep);
            strCipherHexArea.setText(toByteHex(cipher));
            strCipherAsciiArea.setText(toDisplayAscii(cipher));
            setStatus("字符串加密完成，密文 " + cipher.length + " 字节");
        });
    }

    private void onStringDecrypt() {
        runSafely(() -> {
            int key = SAESCore.parseBits(strKeyField.getText(), 16, "密钥");
            byte[] cipher = parseByteHex(strCipherHexArea.getText());
            logHeader("字符串解密（" + cipher.length / 2 + " 组）");
            byte[] plain = SAESCore.decryptBytes(cipher, key, this::logStep);
            strPlainArea.setText(new String(plain, java.nio.charset.StandardCharsets.ISO_8859_1));
            strCipherAsciiArea.setText(toDisplayAscii(cipher));
            setStatus("字符串解密完成");
        });
    }

    private void onMultiEncrypt() {
        runSafely(() -> {
            int mode = multiModeBox.getSelectedIndex();
            long key = MultiSAES.parseKey(multiKeyField.getText(), currentKeyBits());
            int plain = SAESCore.parseBits(multiPlainField.getText(), 16, "明文");
            int cipher = switch (mode) {
                case 0 -> MultiSAES.doubleEncrypt(plain, key);
                case 1 -> MultiSAES.tripleEncrypt(plain, key, MultiSAES.TripleMode.KEY_32);
                default -> MultiSAES.tripleEncrypt(plain, key, MultiSAES.TripleMode.KEY_48);
            };
            multiCipherField.setText(SAESCore.toBits(cipher, 16));
            logHeader(multiModeBox.getSelectedItem() + " 加密");
            log("  明文 P = " + SAESCore.toBits(plain, 16) + "，密文 C = " + SAESCore.toBits(cipher, 16));
            setStatus("多重加密完成");
        });
    }

    private void onMultiDecrypt() {
        runSafely(() -> {
            int mode = multiModeBox.getSelectedIndex();
            long key = MultiSAES.parseKey(multiKeyField.getText(), currentKeyBits());
            int cipher = SAESCore.parseBits(multiCipherField.getText(), 16, "密文");
            int plain = switch (mode) {
                case 0 -> MultiSAES.doubleDecrypt(cipher, key);
                case 1 -> MultiSAES.tripleDecrypt(cipher, key, MultiSAES.TripleMode.KEY_32);
                default -> MultiSAES.tripleDecrypt(cipher, key, MultiSAES.TripleMode.KEY_48);
            };
            multiPlainField.setText(SAESCore.toBits(plain, 16));
            logHeader(multiModeBox.getSelectedItem() + " 解密");
            log("  密文 C = " + SAESCore.toBits(cipher, 16) + "，明文 P = " + SAESCore.toBits(plain, 16));
            setStatus("多重解密完成");
        });
    }

    private void onMitmDemo() {
        long secret = RANDOM.nextLong() & 0xFFFFFFFFL;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 3; i++) {
            int plain = RANDOM.nextInt(65536);
            int cipher = MultiSAES.doubleEncrypt(plain, secret);
            sb.append(SAESCore.toBits(plain, 16)).append(' ').append(SAESCore.toBits(cipher, 16)).append('\n');
        }
        mitmPairsArea.setText(sb.toString().trim());
        mitmHint.setText("演示用的真实密钥（攻击完成后用来核对）：" + SAESCore.toBits(secret, 32));
        mitmHint.setForeground(TEXT_SUB);
        mitmResultArea.setText("");
    }

    private void onMitm() {
        final int[][] pairs;
        try {
            pairs = parsePairs(mitmPairsArea.getText());
        } catch (IllegalArgumentException ex) {
            showError(ex.getMessage());
            return;
        }
        final int[] plains = new int[pairs.length];
        final int[] ciphers = new int[pairs.length];
        for (int i = 0; i < pairs.length; i++) {
            plains[i] = pairs[i][0];
            ciphers[i] = pairs[i][1];
        }
        mitmRunButton.setEnabled(false);
        mitmResultArea.setText("正在攻击...");
        setStatus("中间相遇攻击运行中");
        new SwingWorker<MultiSAES.MitmResult, Void>() {
            @Override
            protected MultiSAES.MitmResult doInBackground() {
                return MultiSAES.meetInTheMiddle(plains, ciphers, 50);
            }

            @Override
            protected void done() {
                mitmRunButton.setEnabled(true);
                try {
                    showMitmResult(get(), plains.length);
                } catch (Exception ex) {
                    showError("攻击失败：" + ex.getMessage());
                }
            }
        }.execute();
    }

    private void showMitmResult(MultiSAES.MitmResult result, int pairCount) {
        StringBuilder sb = new StringBuilder();
        sb.append("使用 ").append(pairCount).append(" 组明密文对，耗时 ").append(result.elapsedMillis).append(" ms\n");
        sb.append("仅用第 1 组对时的候选密钥数：").append(result.firstPairCandidates).append('\n');
        sb.append("与全部 ").append(pairCount).append(" 组对都吻合的密钥数：").append(result.totalMatched).append('\n');
        int shown = 0;
        for (long key : result.keys) {
            sb.append("  K1+K2 = ").append(SAESCore.toBits(key, 32))
                    .append("  (0x").append(String.format("%08X", key)).append(")\n");
            if (++shown >= 20) {
                sb.append("  ...（只显示前 20 个）\n");
                break;
            }
        }
        if (result.totalMatched == 0) sb.append("没有找到密钥：请检查明密文对是否来自同一把 32 位密钥的双重加密。\n");
        mitmResultArea.setText(sb.toString());
        logHeader("中间相遇攻击");
        for (String line : sb.toString().split("\n")) log("  " + line);
        setStatus("中间相遇攻击完成，耗时 " + result.elapsedMillis + " ms");
    }

    private void onCbcEncrypt() {
        runSafely(() -> {
            int key = SAESCore.parseBits(cbcKeyField.getText(), 16, "密钥");
            int iv = SAESCore.parseBits(cbcIvField.getText(), 16, "初始向量");
            String text = cbcPlainArea.getText();
            if (text.isEmpty()) throw new IllegalArgumentException("请输入要加密的明文");
            int[] cipher = CBCMode.encryptText(text, key, iv);
            cbcCipherArea.setText(CBCMode.formatHex(cipher));
            logHeader("CBC 加密（IV = " + SAESCore.toBits(iv, 16) + "）");
            int[] plainBlocks = SAESCore.bytesToBlocks(SAESCore.asciiBytes(text));
            int previous = iv;
            for (int i = 0; i < plainBlocks.length; i++) {
                log(String.format("  第 %d 块：P=%s XOR 前一密文=%s -> 加密 -> C=%s", i + 1,
                        SAESCore.toHex(plainBlocks[i]), SAESCore.toHex(previous), SAESCore.toHex(cipher[i])));
                previous = cipher[i];
            }
            setStatus("CBC 加密完成，共 " + cipher.length + " 块");
        });
    }

    private void onCbcDecrypt() {
        runSafely(() -> {
            int key = SAESCore.parseBits(cbcKeyField.getText(), 16, "密钥");
            int iv = SAESCore.parseBits(cbcIvField.getText(), 16, "初始向量");
            int[] cipher = CBCMode.parseHex(cbcCipherArea.getText());
            String text = CBCMode.decryptToText(cipher, key, iv);
            cbcPlainArea.setText(text);
            logHeader("CBC 解密");
            log("  明文：" + toDisplayAscii(text.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
            setStatus("CBC 解密完成");
        });
    }

    private void onCbcTamper() {
        runSafely(() -> {
            int key = SAESCore.parseBits(cbcKeyField.getText(), 16, "密钥");
            int iv = SAESCore.parseBits(cbcIvField.getText(), 16, "初始向量");
            int[] cipher = CBCMode.parseHex(cbcCipherArea.getText());
            int index = (Integer) tamperIndexSpinner.getValue() - 1;
            CBCMode.TamperMode mode = (CBCMode.TamperMode) tamperModeBox.getSelectedItem();
            int[] tampered = CBCMode.tamper(cipher, index, mode);

            int[] plainOriginal = CBCMode.decryptBlocks(cipher, key, iv);
            int[] plainTampered = CBCMode.decryptBlocks(tampered, key, iv);
            cbcOriginalResult.setText(toDisplayAscii(trimPad(SAESCore.blocksToBytes(plainOriginal))));
            cbcTamperedResult.setText(toDisplayAscii(trimPad(SAESCore.blocksToBytes(plainTampered))));

            cbcTableModel.setRowCount(0);
            StringBuilder changedBlocks = new StringBuilder();
            for (int i = 0; i < cipher.length; i++) {
                boolean changed = plainOriginal[i] != plainTampered[i];
                if (changed) changedBlocks.append(i + 1).append(' ');
                cbcTableModel.addRow(new Object[]{i + 1,
                        SAESCore.toHex(cipher[i]), SAESCore.toHex(tampered[i]),
                        SAESCore.toHex(plainOriginal[i]), SAESCore.toHex(plainTampered[i]),
                        changed ? "是" : "否"});
            }
            if (mode != null) {
                logHeader("CBC 密文篡改：" + mode.label.replace("N", String.valueOf(index + 1)));
            }
            log("  原密文  ：" + CBCMode.formatHex(cipher));
            log("  篡改后  ：" + CBCMode.formatHex(tampered));
            log("  原解密  ：" + toDisplayAscii(trimPad(SAESCore.blocksToBytes(plainOriginal))));
            log("  篡改解密：" + toDisplayAscii(trimPad(SAESCore.blocksToBytes(plainTampered))));
            log("  明文发生变化的块：" + (changedBlocks.isEmpty() ? "无" : changedBlocks.toString().trim()));
            setStatus("篡改对比完成：变化的明文块 " + (changedBlocks.isEmpty() ? "无" : changedBlocks.toString().trim()));
        });
    }

    // ==================== 辅助方法 ====================

    private int currentKeyBits() {
        return multiModeBox.getSelectedIndex() == 2 ? 48 : 32;
    }

    private void updateMultiHint() {
        int bits = currentKeyBits();
        multiKeyHint.setText("当前方式需要 " + bits + " 位密钥（现有 "
                + multiKeyField.getText().replaceAll("\\s+", "").length() + " 位）");
        multiKeyHint.setFont(FontProvider.hint());
        multiKeyHint.setForeground(TEXT_SUB);
        String key = multiKeyField.getText().replaceAll("\\s+", "");
        if (key.length() != bits) {
            // 切换方式时自动不齐/截断，免得用户手动改
            String padded = (key + "0".repeat(48)).substring(0, bits);
            multiKeyField.setText(padded);
            multiKeyHint.setText("当前方式需要 " + bits + " 位密钥");
        }
    }

    private static int[][] parsePairs(String text) {
        List<int[]> pairs = new ArrayList<>();
        int lineNo = 0;
        for (String line : text.split("\\R")) {
            lineNo++;
            if (line.isBlank()) continue;
            String[] parts = line.trim().split("\\s+");
            if (parts.length != 2) {
                throw new IllegalArgumentException("第 " + lineNo + " 行格式不对，应为：16位明文 16位密文");
            }
            pairs.add(new int[]{
                    SAESCore.parseBits(parts[0], 16, "第 " + lineNo + " 行明文"),
                    SAESCore.parseBits(parts[1], 16, "第 " + lineNo + " 行密文")});
        }
        if (pairs.isEmpty()) throw new IllegalArgumentException("请至少输入一组明密文对");
        return pairs.toArray(new int[0][]);
    }

    /** 字节 -> "2B 91 7F ..." */
    private static String toByteHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02X", data[i] & 0xFF));
        }
        return sb.toString();
    }

    private static byte[] parseByteHex(String hex) {
        String clean = hex.replaceAll("\\s+", "");
        if (clean.isEmpty() || clean.length() % 4 != 0 || !clean.matches("[0-9A-Fa-f]+")) {
            throw new IllegalArgumentException("密文必须是十六进制，且字节数为 2 的倍数（每 4 个十六进制字符一组）");
        }
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(clean.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    /** 不可见字符用 · 代替，便于在界面显示“乱码”密文 */
    private static String toDisplayAscii(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            int v = b & 0xFF;
            sb.append(v >= 32 && v < 127 ? (char) v : '·');
        }
        return sb.toString();
    }

    private static byte[] trimPad(byte[] data) {
        return SAESCore.stripZeroPad(data);
    }

    private void runSafely(Runnable action) {
        try {
            action.run();
        } catch (IllegalArgumentException ex) {
            showError(ex.getMessage());
        }
    }

    private void showError(String message) {
        setStatus("错误：" + message);
        JOptionPane.showMessageDialog(this, message, "输入有误", JOptionPane.WARNING_MESSAGE);
    }

    private void setStatus(String text) {
        statusLabel.setText(text);
    }

    private void log(String line) {
        logArea.append(line + "\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }

    private void logHeader(String title) {
        log("========== " + title + " ==========");
    }

    private void logStep(String name, String value) {
        log("  " + padRight(name) + ": " + value);
    }

    /** 按显示宽度不空格（中文字符占 2 格），让日志里的冒号对齐 */
    private static String padRight(String text) {
        int width = 0;
        for (char ch : text.toCharArray()) width += ch > 0x7F ? 2 : 1;
        return text + " ".repeat(Math.max(1, 24 - width));
    }

    // ==================== 控件样式 ====================

    /** 放进 JScrollPane 时宽度跟随视口、只在垂直方向滚动的面板 */
    private static class TabPanel extends JPanel implements Scrollable {
        @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }
        @Override public int getScrollableUnitIncrement(Rectangle r, int orientation, int direction) { return 16; }
        @Override public int getScrollableBlockIncrement(Rectangle r, int orientation, int direction) { return 96; }
        @Override public boolean getScrollableTracksViewportWidth() { return true; }
        @Override public boolean getScrollableTracksViewportHeight() { return false; }
    }

    private JPanel newTab() {
        JPanel tab = new TabPanel();
        tab.setLayout(new BoxLayout(tab, BoxLayout.Y_AXIS));
        tab.setBackground(CREAM_BG);
        tab.setBorder(new EmptyBorder(12, 14, 12, 14));
        return tab;
    }

    private JPanel newCard(String title) {
        // 卡片只占用自己需要的高度，多余空间留在标签页底部，避免内容被拉伸居中
        JPanel card = new JPanel(new GridBagLayout()) {
            @Override
            public Dimension getMaximumSize() {
                return new Dimension(Integer.MAX_VALUE, getPreferredSize().height);
            }
        };
        card.setBackground(CREAM_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(new LineBorder(SOFT_LINE, 1, true), " " + title + " ",
                        javax.swing.border.TitledBorder.LEFT, javax.swing.border.TitledBorder.TOP,
                        FontProvider.sectionTitle(), GREEN_DARK),
                new EmptyBorder(10, 12, 10, 12)));
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        return card;
    }

    private GridBagConstraints gbc(int x, int y, int width) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = x;
        c.gridy = y;
        c.gridwidth = width;
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        c.insets = new Insets(5, 4, 5, 4);
        return c;
    }

    private int rowCounter(JPanel card) {
        int max = -1;
        for (Component comp : card.getComponents()) {
            GridBagConstraints gc = ((GridBagLayout) card.getLayout()).getConstraints(comp);
            max = Math.max(max, gc.gridy);
        }
        return max + 1;
    }

    private void addRow(JPanel card, String label, JComponent field) {
        addRow(card, label, field, null);
    }

    private void addRow(JPanel card, String label, JComponent field, JComponent extra) {
        int row = rowCounter(card);
        GridBagConstraints lc = gbc(0, row, 1);
        lc.weightx = 0;
        lc.fill = GridBagConstraints.NONE;
        lc.anchor = GridBagConstraints.NORTHWEST;
        card.add(makeLabel(label), lc);

        styleField(field);
        GridBagConstraints fc = gbc(1, row, extra == null ? 2 : 1);
        if (field instanceof JScrollPane) fc.fill = GridBagConstraints.BOTH;
        card.add(field, fc);
        if (extra != null) {
            GridBagConstraints ec = gbc(2, row, 1);
            ec.weightx = 0;
            ec.fill = GridBagConstraints.NONE;
            card.add(extra, ec);
        }
    }

    private void styleField(JComponent field) {
        if (field instanceof JTextField tf) {
            tf.setFont(FontProvider.input());
            tf.setForeground(TEXT_MAIN);
            tf.setBorder(BorderFactory.createCompoundBorder(
                    new LineBorder(SOFT_LINE, 1, true), new EmptyBorder(4, 8, 4, 8)));
        } else if (field instanceof JLabel lb) {
            lb.setFont(FontProvider.hint());
            lb.setForeground(TEXT_SUB);
        } else if (field instanceof JComboBox<?> box) {
            box.setFont(FontProvider.body());
        }
    }

    private JScrollPane scroll(JTextArea area) {
        area.setFont(FontProvider.input());
        area.setLineWrap(true);
        area.setWrapStyleWord(false);
        area.setBorder(new EmptyBorder(4, 8, 4, 8));
        JScrollPane sp = new JScrollPane(area);
        sp.setBorder(new LineBorder(SOFT_LINE, 1, true));
        return sp;
    }

    private JLabel makeLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(FontProvider.label());
        label.setForeground(TEXT_MAIN);
        return label;
    }

    private JLabel hintLabel(String text) {
        JLabel label = new JLabel("<html><body style='width:700px'>" + text + "</body></html>");
        label.setFont(FontProvider.hint());
        label.setForeground(TEXT_SUB);
        label.setBorder(new EmptyBorder(8, 4, 0, 4));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    private JPanel buttonRow(JButton... buttons) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 4));
        row.setOpaque(false);
        for (JButton b : buttons) row.add(b);
        return row;
    }

    private static JButton makeButton(String text, boolean primary) {
        JButton button = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                Color fill;
                if (primary) fill = !isEnabled() ? GREEN_LIGHT : getModel().isRollover() ? GREEN_DARK : GREEN;
                else fill = getModel().isRollover() ? new Color(0xEDE7D8) : CREAM_CARD;
                g2.setColor(fill);
                g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 12, 12);
                if (!primary) {
                    g2.setColor(GREEN_LIGHT);
                    g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 12, 12);
                }
                g2.dispose();
                super.paintComponent(g);
            }
        };
        button.setFont(FontProvider.button());
        button.setForeground(primary ? Color.WHITE : GREEN_DARK);
        button.setFocusPainted(false);
        button.setBorderPainted(false);
        button.setContentAreaFilled(false);
        button.setOpaque(false);
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));
        button.setBorder(new EmptyBorder(8, 18, 8, 18));
        return button;
    }

    private static JButton makeButton(String text, boolean primary, java.awt.event.ActionListener listener) {
        JButton button = makeButton(text, primary);
        button.addActionListener(listener);
        return button;
    }
}
