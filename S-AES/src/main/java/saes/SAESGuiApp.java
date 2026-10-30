package saes;

import javax.swing.*;
import java.awt.*;
import java.util.Objects;

/**
 * S-AES 图形界面入口：创建窗口并放入 SAESMainPanel。
 * 运行：java -cp out saes.SAESGuiApp
 */
public final class SAESGuiApp {


    private SAESGuiApp() {}

    public static void main(String[] args) {
        System.setProperty("awt.useSystemAAFontSettings", "on");
        System.setProperty("swing.aatext", "true");
        SwingUtilities.invokeLater(SAESGuiApp::showWindow);
    }

    private static void showWindow() {
        JFrame frame = new JFrame("S-AES 加解密工具");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        try {
            Image icon = javax.imageio.ImageIO.read(Objects.requireNonNull(SAESGuiApp.class.getResourceAsStream("/icon.png")));
            if (icon != null) frame.setIconImage(icon);
        } catch (Exception ignored) {
            // 没有图标资源时使用默认图标
        }
        frame.setContentPane(new SAESMainPanel());
        frame.setSize(900, 780);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }
}
