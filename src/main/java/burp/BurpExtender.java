package burp;


import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;


import java.io.*;
import java.util.*;
import java.util.List;
import javax.swing.*;


public class BurpExtender implements IBurpExtender, ITab, ActionListener, IContextMenuFactory, MouseListener, IExtensionStateListener, IIntruderPayloadProcessor, IHttpListener {

    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private PrintWriter stderr;

    private final Crypto CryptoView = new Crypto();
    private JPanel mainPanel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks c) {

        // Keep a reference to our callbacks object
        this.callbacks = c;

        // Obtain an extension helpers object
        //IExtensionHelpers helpers = callbacks.getHelpers();

        // Set our extension name
        callbacks.setExtensionName("HBurp");

        // register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(this);

        //register to produce options for the context menu
        callbacks.registerContextMenuFactory(this);

        // register to execute actions on unload
        callbacks.registerExtensionStateListener(this);

        // Initialize stdout and stderr
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        stdout.println("Github: https://github.com/hypdncy/HBurp");

        //构造画面
        SwingUtilities.invokeLater(() -> {
            mainPanel = new JPanel();
            mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
            final JTabbedPane mainTable = new JTabbedPane();
            mainTable.add("crypto", drawCryptoView());
            mainPanel.add(mainTable);
            callbacks.customizeUiComponent(mainPanel);
            callbacks.addSuiteTab(BurpExtender.this);
        });
        callbacks.registerHttpListener(this);

    }

    private Component drawCryptoView() {
        return CryptoView.$$$getRootComponent$$$();
    }


    // config Override
    // 定义界面
    @Override
    public String getTabCaption() {
        return "HBurp";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    @Override
    public void actionPerformed(ActionEvent event) {
    }

    // 创建右键菜单
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {

        List<JMenuItem> cryptoMenu = CryptoView.createMenuItems(invocation, callbacks);
        cryptoMenu.forEach((item) -> item.addActionListener(this));

        return new ArrayList<>(cryptoMenu);
    }

    @Override
    public void mouseClicked(MouseEvent e) {

    }

    @Override
    public void mousePressed(MouseEvent e) {

    }

    @Override
    public void mouseReleased(MouseEvent e) {

    }

    @Override
    public void mouseEntered(MouseEvent e) {
    }

    @Override
    public void mouseExited(MouseEvent e) {
    }

    @Override
    public void extensionUnloaded() {

    }

    @Override
    public String getProcessorName() {
        return "Burpy processor";
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        return currentPayload;
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

    }

}


