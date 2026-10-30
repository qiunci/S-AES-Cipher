package saes;

import java.awt.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * 字体提供者：探测系统中真正可用的中英文字体，
 * 并提供一套分层级的字体常量，用于界面美化。
 * <p>
 * 字体性格：
 *   - TITLE 衬线（宋体系）：标题、状态栏
 *   - UI    无衬线（雅黑系）：标签、按钮、Tab
 *   - MONO  等宽（Monospaced）：输入框、日志
 * <p>
 * 字号层级（从大到小）：
 *   24  应用主标题
 *   16  区块标题
 *   14  输入框内容
 *   13  字段标签、按钮、Tab、日志
 *   12  提示文字
 *   11  底部状态
 */
public final class FontProvider {

    private FontProvider() {}

    private static final Set<String> AVAILABLE = new HashSet<>();
    static {
        String[] names = GraphicsEnvironment.getLocalGraphicsEnvironment()
                .getAvailableFontFamilyNames();
        AVAILABLE.addAll(Arrays.asList(names));
    }

    private static String firstAvailable(String fallback, String... candidates) {
        for (String name : candidates) {
            if (AVAILABLE.contains(name)) return name;
        }
        return fallback;
    }

    // ============ 三套字体族 ============

    /** 正文族：无衬线，现代 */
    private static final String UI_FAMILY = firstAvailable(
            "Dialog",
            "Microsoft YaHei UI",
            "Microsoft YaHei", "微软雅黑",
            "PingFang SC", "苹方-简",
            "Noto Sans CJK SC",
            "Source Han Sans SC",
            "WenQuanYi Micro Hei",
            "SimHei", "黑体"
    );

    /** 输入框（纯 ASCII：0/1 和十六进制）：用英文等宽字体 */
    private static final String INPUT_FAMILY = firstAvailable(
            "Monospaced",
            "Cascadia Mono", "Consolas", "Menlo", "SF Mono", "Monaco",
            "JetBrains Mono", "DejaVu Sans Mono", "Courier New");

    /** 日志（含中文和符号）：只选能显示中文的字体，找不到就退到正文字体 */
    private static final String LOG_FAMILY = firstDisplayable(
            UI_FAMILY,
            "Sarasa Mono SC", "Sarasa Term SC", "Microsoft YaHei Mono",
            "Noto Sans Mono CJK SC", "WenQuanYi Zen Hei Mono");

    /** 等宽族：日志与二进制位串，等宽更整齐 */
    private static final String MONO_FAMILY = firstAvailable(
            "Monospaced",
            "Sarasa Mono SC", "Sarasa Term SC",     // 更纱黑体（装了最好看）
            "Cascadia Mono", "Consolas",            // Windows
            "Menlo", "SF Mono", "Monaco",           // macOS
            "JetBrains Mono", "Fira Code",
            "DejaVu Sans Mono",                     // Linux
            "Noto Sans Mono CJK SC", "Courier New"
    );

    private static final String LOG_SAMPLE = "中文测试═→⊕·0123";

    /** 只选能完整显示样本字符串的字体 */
    private static String firstDisplayable(String fallback, String... candidates) {
        for (String name : candidates) {
            if (AVAILABLE.contains(name)
                    && new Font(name, Font.PLAIN, 13).canDisplayUpTo(LOG_SAMPLE) == -1) {
                return name;
            }
        }
        return fallback;
    }

    public static Font ui(int style, int size)    { return new Font(UI_FAMILY, style, size); }
    public static Font mono(int style, int size)  { return new Font(MONO_FAMILY, style, size); }

    // ============ 界面专用字体（直接调用，无需记字号） ============

    /** 应用主标题：衬线 24 Bold */
    public static Font appTitle()    { return ui(Font.BOLD, 26); }
    public static Font appSubtitle() { return ui(Font.PLAIN, 12); }   // 原来是 ITALIC

    /** 区块标题：雅黑 15 Bold */
    public static Font sectionTitle()  { return ui(Font.BOLD, 15); }

    public static Font label()       { return ui(Font.PLAIN, 13); }   // 原来是 BOLD

    /** 普通正文：雅黑 13 Plain */
    public static Font body()          { return ui(Font.PLAIN, 13); }

    /** 按钮：雅黑 13 Bold */
    public static Font button()        { return ui(Font.BOLD, 13); }

    public static Font tab()         { return ui(Font.PLAIN, 13); }   // 原来是 BOLD

    public static Font input() { return new Font(INPUT_FAMILY, Font.PLAIN, 14); }
    public static Font log()   { return new Font(LOG_FAMILY,   Font.PLAIN, 13); }

    /** 提示文字：雅黑 12 Plain */
    public static Font hint()          { return ui(Font.PLAIN, 12); }

    public static Font status()      { return ui(Font.PLAIN, 12); }   // 原来是 ITALIC
}