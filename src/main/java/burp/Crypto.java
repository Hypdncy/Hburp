package burp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import java.awt.*;
import javax.swing.JComboBox;
import javax.swing.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.net.http.*;
import java.net.URL;
import java.net.URI;

import java.security.Security;
import java.util.*;
import java.util.List;
import java.util.ArrayList;


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

public class Crypto {
    private JPanel mainJPanel;
    private JTextField serverStatusJTextField;
    private JTextField remoteUrlJTextField;
    private JTextField remotePwdJTextField;
    private JTextField secretKeyJTextField;
    private JTextField secretIVATextField;
    private JCheckBox checkLocal;
    private JCheckBox checkRemote;
    private JComboBox secretTypeBox;
    private JComboBox secretModBox;
    private JComboBox secretCodeBox;
    private JComboBox secretPadBox;
    private JButton startButton;
    private JButton stopButton;
    private JButton cleanButton;
    private JTextArea consoleLogText;

    private final String HBURP_DECRYPTO = "DECRYPTO";
    private final String HBURP_ENCRYPTO = "ENCRYPTO";
    private final String HBURP_FAILED = "Hburp-Failed";

    private int serverStatus = -1;

    private String remoteHttpURL;
    private String remoteHttpPwd;
    private URL remoteURLHttpUrl;


    private String secretType;
    private String secretMod;
    private String secretCode;
    private String secretPad;
    private String secretKey;
    private String secretIV;


    public void setDisableEdit() {
        remoteUrlJTextField.setEnabled(false);
        remotePwdJTextField.setEnabled(false);
        secretKeyJTextField.setEnabled(false);
        secretIVATextField.setEnabled(false);
        checkLocal.setEnabled(false);
        checkRemote.setEnabled(false);
        secretTypeBox.setEnabled(false);
        secretPadBox.setEnabled(false);
        secretCodeBox.setEnabled(false);
        secretModBox.setEnabled(false);
    }

    public void setEnableEdit() {
        remoteUrlJTextField.setEnabled(true);
        remotePwdJTextField.setEnabled(true);
        secretKeyJTextField.setEnabled(true);
        secretIVATextField.setEnabled(true);
        checkLocal.setEnabled(true);
        checkRemote.setEnabled(true);
        secretTypeBox.setEnabled(true);
        secretPadBox.setEnabled(true);
        secretCodeBox.setEnabled(true);
        secretModBox.setEnabled(true);

    }

    public void getComponentTextValue() {
        remoteHttpURL = remoteUrlJTextField.getText();
        remoteHttpPwd = remotePwdJTextField.getText();

        secretType = (String) secretTypeBox.getSelectedItem();
        secretMod = (String) secretModBox.getSelectedItem();
        secretCode = (String) secretCodeBox.getSelectedItem();
        secretPad = (String) secretPadBox.getSelectedItem();

        secretKey = secretKeyJTextField.getText();
        secretIV = secretIVATextField.getText();
    }

    public void checkRemoteConfig() {


        new Thread(() -> {
            try {
                remoteURLHttpUrl = new URL(remoteHttpURL);
                HttpClient client = HttpClient.newHttpClient();
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(remoteHttpURL + "test"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(remoteHttpPwd))
                        .build();

                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    serverStatus = -1;
                }
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
                consoleLogText.setText(consoleLogColor("checkRemoteConfig Failed", "red"));
                serverStatus = -1;
            }
        }).start();
    }

    public String consoleLogColor(String consoleText, String color) {
        List<String> colors = new ArrayList<>();
        colors.add("green");
        colors.add("red");
        String newConsoleText;
        if (colors.contains(color)) {
            newConsoleText = "<font color=\"" + color + "\"><b>" + consoleText + "</b><br/></font><br/>";
        } else {
            newConsoleText = consoleText;
        }
        return newConsoleText;

    }

    public Crypto() {
        consoleLogText.setLineWrap(true);
        consoleLogText.setEditable(false);

        checkLocal.addActionListener(e -> checkRemote.setSelected(false));
        checkRemote.addActionListener(e -> checkLocal.setSelected(false));
        startButton.addActionListener(e -> {
            setDisableEdit();
            getComponentTextValue();
            if (checkLocal.isSelected()) {
                serverStatus = 1;
                if (secretKey.length() != 16) {
                    consoleLogText.setText(consoleLogColor("secretKey length not equal 16", "red"));
                    serverStatus = -1;
                }
            } else if (checkRemote.isSelected()) {
                serverStatus = 2;
                checkRemoteConfig();
            }
            if (serverStatus > 0) {
                serverStatusJTextField.setText("Running");
                startButton.setSelected(true);
            }
        });
        stopButton.addActionListener(e -> {
            setEnableEdit();
            serverStatusJTextField.setText("Stopping");
            serverStatus = -1;
            startButton.setSelected(false);
        });
    }


    public byte[] getCryptoRequest(IBurpExtenderCallbacks callbacks, List<String> headers, byte[] body, String style) {
        IExtensionHelpers helpers = callbacks.getHelpers();

        headers.set(0, "Url: " + headers.get(0));
        for (int i = 0; i < headers.size(); i++) {
            headers.set(i, "Hburp-" + headers.get(i));
        }

        headers.add(0, "Accept: */*");
        headers.add(0, "Content-Type: application/x-www-form-urlencoded");
        headers.add(0, "Connection: close");
        headers.add(0, "Host: " + remoteURLHttpUrl.getHost() + ":" + remoteURLHttpUrl.getDefaultPort());
        headers.add(0, "POST " + remoteURLHttpUrl.getFile() + style + " HTTP/1.1");


        return helpers.buildHttpMessage(headers, body);
    }

    public byte[] getCryptoResponse(IBurpExtenderCallbacks callbacks, byte[] response) {
        IExtensionHelpers helpers = callbacks.getHelpers();
        IRequestInfo responseInfo = helpers.analyzeRequest(response);
        List<String> responseHeaders = responseInfo.getHeaders();
        List<String> newResponseHeaders = new ArrayList<>();

        responseHeaders.forEach((responseHeader) -> {
            if (responseHeader.startsWith("Hburp-Url: ")) {
                newResponseHeaders.add(0, responseHeader.substring(11));
            } else if (responseHeader.startsWith("Hburp-")) {
                newResponseHeaders.add(responseHeader.substring(6));
            }
        });
        byte[] responseBody = Arrays.copyOfRange(response, responseInfo.getBodyOffset(), response.length);
        return helpers.buildHttpMessage(newResponseHeaders, responseBody);
    }

    public byte[] encryptAES(byte[] body) {
        try {
            switch (secretPad) {
                //不支持ZEROPadding
                case "NOPadding":
                    int len = body.length;
                    int m = len % 16;
                    if (m != 0) {
                        byte[] newBody = new byte[len + 16];
                        System.arraycopy(body, 0, newBody, 0, len);
                        body = newBody;
                    }
                    break;
                case "PKCS7Padding":
                    Security.addProvider(new BouncyCastleProvider());
                    break;
                default:
                    break;
            }

            SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance("AES/" + secretMod + "/" + secretPad);

            if (Objects.equals(secretMod, "ECB")) {
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            } else {
                IvParameterSpec iv = new IvParameterSpec(secretIV.getBytes(StandardCharsets.UTF_8));
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
            }
            byte[] encrypted = cipher.doFinal(body);
            Encoder encoder = Base64.getEncoder();
            return encoder.encode(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return HBURP_FAILED.getBytes();
        }
    }

    public byte[] decryptAES(byte[] body) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
            IvParameterSpec iv = new IvParameterSpec(secretIV.getBytes(StandardCharsets.UTF_8));
            Cipher cipher = Cipher.getInstance("AES/" + secretMod + "/" + secretPad);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
            Decoder decoder = Base64.getDecoder();
            byte[] encrypted = decoder.decode(body);//先用base64解密
            return cipher.doFinal(encrypted);

        } catch (Exception ex) {
            return HBURP_FAILED.getBytes();
        }
    }


    public void cryptoHandle(IContextMenuInvocation invocation, IBurpExtenderCallbacks callbacks, String crypto) {

        if (serverStatus < 0) {
            return;
        }
        IHttpRequestResponse[] selectedItems = invocation.getSelectedMessages();
        byte selectedInvocationContext = invocation.getInvocationContext();
        IExtensionHelpers helpers = callbacks.getHelpers();

        byte[] oldRequestOrResponse;
        byte[] oldRequestOrResponseBody;
        List<String> oldRequestOrResponseHeaders;
        byte[] newRequestOrResponse = null;
        byte[] newRequestOrResponseBody = null;

        if (selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
            oldRequestOrResponse = selectedItems[0].getRequest();
            IRequestInfo requestInfo = helpers.analyzeRequest(oldRequestOrResponse);
            oldRequestOrResponseBody = Arrays.copyOfRange(oldRequestOrResponse, requestInfo.getBodyOffset(), oldRequestOrResponse.length);
            oldRequestOrResponseHeaders = requestInfo.getHeaders();
        } else {
            oldRequestOrResponse = selectedItems[0].getResponse();
            IResponseInfo responseInfo = helpers.analyzeResponse(oldRequestOrResponse);
            oldRequestOrResponseBody = Arrays.copyOfRange(oldRequestOrResponse, responseInfo.getBodyOffset(), oldRequestOrResponse.length);
            oldRequestOrResponseHeaders = responseInfo.getHeaders();
        }

        if (serverStatus == 1) {

            if (Objects.equals(crypto, HBURP_DECRYPTO)) {
                if (Objects.equals(secretType, "AES")) {
                    newRequestOrResponseBody = decryptAES(oldRequestOrResponseBody);
                }
            } else if (Objects.equals(crypto, HBURP_ENCRYPTO)) {
                if (Objects.equals(secretType, "AES")) {
                    newRequestOrResponseBody = encryptAES(oldRequestOrResponseBody);
                }
            }
            newRequestOrResponse = helpers.buildHttpMessage(oldRequestOrResponseHeaders, newRequestOrResponseBody);

        } else if (serverStatus == 2) {
            byte[] reqCryptoResponse = callbacks.makeHttpRequest(remoteURLHttpUrl.getHost(), remoteURLHttpUrl.getDefaultPort(), false,
                    getCryptoRequest(callbacks, oldRequestOrResponseHeaders, oldRequestOrResponse, crypto));
            newRequestOrResponse = getCryptoResponse(callbacks, reqCryptoResponse);

        }
        if (selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
            selectedItems[0].setRequest(newRequestOrResponse);
        } else if (selectedInvocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE) {
            selectedItems[0].setResponse(newRequestOrResponse);
        } else {
            assert newRequestOrResponseBody != null;
            MessageDialog.show("Hburp " + crypto, new String(newRequestOrResponseBody));
        }
    }

    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation, IBurpExtenderCallbacks callbacks) {
        List<JMenuItem> menu = new ArrayList<>();
        JMenuItem enItem = new JMenuItem("Hburp Encrypto");
        JMenuItem deItem = new JMenuItem("Hburp Decrypto");

        enItem.addActionListener(e -> new Thread(() -> cryptoHandle(invocation, callbacks, HBURP_ENCRYPTO)).start());
        deItem.addActionListener(e -> new Thread(() -> cryptoHandle(invocation, callbacks, HBURP_DECRYPTO)).start());
        enItem.setActionCommand("Hburp-Encrypto");
        deItem.setActionCommand("Hburp-Decrypto");

        menu.add(enItem);
        menu.add(deItem);
        return menu;
    }


    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        mainJPanel = new JPanel();
        mainJPanel.setLayout(new GridLayoutManager(4, 2, new Insets(0, 0, 0, 0), -1, -1));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(8, 5, new Insets(0, 0, 0, 0), -1, -1));
        mainJPanel.add(panel1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("Server Status:");
        panel1.add(label1, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        serverStatusJTextField = new JTextField();
        serverStatusJTextField.setEditable(false);
        serverStatusJTextField.setText("Stopping");
        panel1.add(serverStatusJTextField, new GridConstraints(2, 1, 1, 4, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Remote Url:");
        panel1.add(label2, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        remoteUrlJTextField = new JTextField();
        remoteUrlJTextField.setText("http://127.0.0.1:80/name/");
        panel1.add(remoteUrlJTextField, new GridConstraints(3, 1, 1, 4, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Remote Pwd:");
        panel1.add(label3, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        remotePwdJTextField = new JTextField();
        remotePwdJTextField.setText("");
        panel1.add(remotePwdJTextField, new GridConstraints(4, 1, 1, 4, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("Secert Mod:");
        panel1.add(label4, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("Secert Key:");
        panel1.add(label5, new GridConstraints(6, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        secretKeyJTextField = new JTextField();
        secretKeyJTextField.setText("");
        panel1.add(secretKeyJTextField, new GridConstraints(6, 1, 1, 4, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label6 = new JLabel();
        label6.setText("Secert IV:");
        panel1.add(label6, new GridConstraints(7, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        secretIVATextField = new JTextField();
        secretIVATextField.setText("");
        panel1.add(secretIVATextField, new GridConstraints(7, 1, 1, 4, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        secretTypeBox = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel1 = new DefaultComboBoxModel();
        defaultComboBoxModel1.addElement("AES");
        defaultComboBoxModel1.addElement("DES");
        secretTypeBox.setModel(defaultComboBoxModel1);
        panel1.add(secretTypeBox, new GridConstraints(5, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        secretPadBox = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel2 = new DefaultComboBoxModel();
        defaultComboBoxModel2.addElement("PKCS5Padding");
        defaultComboBoxModel2.addElement("PKCS7Padding");
        defaultComboBoxModel2.addElement("NOPadding");
        defaultComboBoxModel2.addElement("ISO10126Padding");
        secretPadBox.setModel(defaultComboBoxModel2);
        panel1.add(secretPadBox, new GridConstraints(5, 4, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        secretCodeBox = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel3 = new DefaultComboBoxModel();
        defaultComboBoxModel3.addElement("Base64");
        defaultComboBoxModel3.addElement("Hex");
        secretCodeBox.setModel(defaultComboBoxModel3);
        panel1.add(secretCodeBox, new GridConstraints(5, 3, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        secretModBox = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel4 = new DefaultComboBoxModel();
        defaultComboBoxModel4.addElement("EBC");
        defaultComboBoxModel4.addElement("CBC");
        defaultComboBoxModel4.addElement("CTR");
        defaultComboBoxModel4.addElement("OFB");
        defaultComboBoxModel4.addElement("CFB");
        secretModBox.setModel(defaultComboBoxModel4);
        panel1.add(secretModBox, new GridConstraints(5, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label7 = new JLabel();
        label7.setText("Crypto Type:");
        panel1.add(label7, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        checkLocal = new JCheckBox();
        checkLocal.setSelected(true);
        checkLocal.setText("Local");
        panel1.add(checkLocal, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label8 = new JLabel();
        label8.setText("Server Start:");
        panel1.add(label8, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        startButton = new JButton();
        startButton.setText("Start");
        panel1.add(startButton, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        stopButton = new JButton();
        stopButton.setText("Stop");
        panel1.add(stopButton, new GridConstraints(1, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cleanButton = new JButton();
        cleanButton.setText("Clean");
        panel1.add(cleanButton, new GridConstraints(1, 3, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        checkRemote = new JCheckBox();
        checkRemote.setEnabled(true);
        checkRemote.setSelected(false);
        checkRemote.setText("Remote");
        panel1.add(checkRemote, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        mainJPanel.add(spacer1, new GridConstraints(0, 1, 2, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        mainJPanel.add(spacer2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        consoleLogText = new JTextArea();
        mainJPanel.add(consoleLogText, new GridConstraints(3, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(150, 50), null, 0, false));
        final JLabel label9 = new JLabel();
        label9.setText("Console Log");
        mainJPanel.add(label9, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainJPanel;
    }

}
