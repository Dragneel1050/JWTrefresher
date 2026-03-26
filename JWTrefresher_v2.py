# -*- coding: utf-8 -*-
# JWT Refresher v3 - Burp Suite Extension
#
# A comprehensive extension to manage and auto-refresh JWT tokens during testing.
# Supports multiple response parsing modes (JSON Path, Regex, String-Escaped JSON),
# auto-refresh on JWT expiry or fixed intervals, and multi-session handling.

# --- Java/Swing Imports ---
from javax.swing import (
    JPanel, JLabel, JTextField, JTextArea, JScrollPane,
    JButton, JCheckBox, BorderFactory, SwingUtilities,
    JRadioButton, ButtonGroup, JComboBox, JSpinner,
    SpinnerNumberModel
)
from java.awt import GridBagLayout, GridBagConstraints, Insets, FlowLayout
from java.net import URL, HttpURLConnection
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader
from java.lang import Thread, Runnable, InterruptedException
from java.util import Base64

# --- Burp Imports ---
from burp import IBurpExtender, ITab, IHttpListener, IExtensionStateListener

# --- Standard Library ---
import json
import re
import time
from threading import Lock


class _AutoRefreshRunnable(Runnable):
    """Background daemon that monitors token expiry and triggers refresh."""

    def __init__(self, extender):
        self.ext = extender

    def run(self):
        while self.ext._running:
            try:
                Thread.sleep(5000)
                if not self.ext.chk_enabled.isSelected():
                    continue
                if not self.ext.radio_active_mode.isSelected():
                    continue

                now = int(time.time())

                # --- Expiry-based auto-refresh ---
                if self.ext.chk_auto_refresh_expiry.isSelected():
                    with self.ext._token_lock:
                        expiry = self.ext._token_expiry
                    if expiry > 0:
                        buffer_sec = int(self.ext.spn_expiry_buffer.getValue())
                        time_left = expiry - now
                        if 0 < time_left <= buffer_sec:
                            self.ext.log("[AUTO] Token expires in {}s. Refreshing...".format(time_left))
                            self.ext.refresh_tokens()
                            continue

                # --- Interval-based auto-refresh ---
                if self.ext.chk_auto_refresh_interval.isSelected():
                    with self.ext._token_lock:
                        last_time = self.ext._last_token_time
                    if last_time > 0:
                        interval_sec = int(self.ext.spn_interval_minutes.getValue()) * 60
                        if (now - last_time) >= interval_sec:
                            self.ext.log("[AUTO] Interval ({}min) reached. Refreshing...".format(interval_sec / 60))
                            self.ext.refresh_tokens()

            except InterruptedException:
                break
            except Exception as e:
                try:
                    self.ext.log("[ERROR] Auto-refresh thread: " + str(e))
                except:
                    pass


class BurpExtender(IBurpExtender, ITab, IHttpListener, IExtensionStateListener):
    """
    JWT Refresher v3 - Manages JWT token lifecycle during Burp Suite testing.

    Modes:
      Active  - Single session, manual or auto refresh via HTTP endpoint.
      Passive - Learns tokens from proxy traffic, supports multi-session.

    Extraction Modes:
      JSON Path         - Navigate nested JSON with dot notation.
      Regex Pattern     - Use capture group () for any text format.
      String-Escaped JSON - Double-parse for string-encoded JSON responses.
    """

    MODE_JSON_PATH = "JSON Path"
    MODE_REGEX = "Regex Pattern"
    MODE_STRING_JSON = "String-Escaped JSON"

    # Burp tool flag constants
    TOOL_PROXY = 4
    TOOL_SCANNER = 16
    TOOL_INTRUDER = 32
    TOOL_REPEATER = 64
    TOOL_EXTENDER = 1024

    # BAC apply-to modes
    BAC_REPEATER_ONLY = "Repeater Only"
    BAC_ALL_TOOLS = "All Tools"
    BAC_ALL_EXCEPT_PROXY = "All Tools Except Proxy"

    # ===================================================================
    # REGISTRATION & LIFECYCLE
    # ===================================================================

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JWT Refresher v3")

        # --- State ---
        self.active_access_token = None
        self.token_cache = {}
        self._running = True
        self._last_token_time = 0
        self._token_expiry = 0

        # --- Locks ---
        self._token_lock = Lock()
        self._refresh_lock = Lock()
        self._cache_lock = Lock()

        # --- Build UI ---
        self._build_ui()
        self._toggle_mode(None)
        self._toggle_extraction_mode(None)

        # --- Register ---
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        # --- Start auto-refresh daemon ---
        t = Thread(_AutoRefreshRunnable(self))
        t.setDaemon(True)
        t.start()

        self._log("[INFO] JWT Refresher v3 loaded successfully.")

    def extensionUnloaded(self):
        self._running = False
        self._log("[INFO] JWT Refresher v3 unloaded.")

    # ===================================================================
    # UI BUILDING
    # ===================================================================

    def _build_ui(self):
        self._main_panel = JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.insets = Insets(5, 5, 5, 5)
        c.anchor = GridBagConstraints.NORTHWEST
        c.fill = GridBagConstraints.HORIZONTAL
        c.weightx = 1.0
        c.gridx = 0

        # --- 1. Operating Mode ---
        c.gridy = 0
        c.weighty = 0
        mode_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        mode_panel.setBorder(BorderFactory.createTitledBorder("1. Operating Mode"))
        self.radio_active_mode = JRadioButton("Active Mode (Single Session)", True)
        self.radio_active_mode.addActionListener(self._toggle_mode)
        self.radio_passive_mode = JRadioButton("Passive Mode (Auto-Learning, Multi-Session)", False)
        self.radio_passive_mode.addActionListener(self._toggle_mode)
        grp = ButtonGroup()
        grp.add(self.radio_active_mode)
        grp.add(self.radio_passive_mode)
        mode_panel.add(self.radio_active_mode)
        mode_panel.add(self.radio_passive_mode)
        self._main_panel.add(mode_panel, c)

        # --- 2. Configuration ---
        c.gridy = 1
        self.config_panel = self._build_config_panel()
        self._main_panel.add(self.config_panel, c)

        # --- 3. Controls ---
        c.gridy = 2
        controls = JPanel(FlowLayout(FlowLayout.CENTER))
        controls.setBorder(BorderFactory.createTitledBorder("Controls"))
        self.btn_refresh = JButton("Get/Refresh Tokens (Active Mode)")
        self.btn_refresh.addActionListener(self._on_refresh_click)
        self.chk_enabled = JCheckBox("Enable Token Handling", False)
        controls.add(self.btn_refresh)
        controls.add(self.chk_enabled)
        self._main_panel.add(controls, c)

        # --- 4. Log & Token ---
        c.gridy = 3
        c.weighty = 1.0
        c.fill = GridBagConstraints.BOTH
        self._main_panel.add(self._build_log_panel(), c)

        # --- 5. Last Transaction ---
        c.gridy = 4
        c.weighty = 1.0
        self.transaction_panel = self._build_transaction_panel()
        self._main_panel.add(self.transaction_panel, c)

    def _build_config_panel(self):
        panel = JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.insets = Insets(2, 5, 2, 5)
        c.anchor = GridBagConstraints.WEST
        c.fill = GridBagConstraints.HORIZONTAL
        c.weightx = 1.0
        c.gridx = 0

        c.gridy = 0
        panel.add(self._build_common_config(), c)
        c.gridy = 1
        panel.add(self._build_extraction_config(), c)
        c.gridy = 2
        self.active_mode_panel = self._build_active_config()
        panel.add(self.active_mode_panel, c)
        c.gridy = 3
        self.passive_mode_panel = self._build_passive_config()
        panel.add(self.passive_mode_panel, c)
        return panel

    # --- Common Config ---

    def _build_common_config(self):
        panel = JPanel(GridBagLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Common Configuration"))
        cc = GridBagConstraints()
        cc.insets = Insets(2, 5, 2, 5)
        cc.anchor = GridBagConstraints.WEST
        cc.fill = GridBagConstraints.HORIZONTAL
        cc.weightx = 1.0

        cc.gridx = 0
        cc.gridy = 0
        cc.gridwidth = 4
        panel.add(JLabel("Token Endpoint URL:"), cc)
        cc.gridy = 1
        self.txt_endpoint = JTextField("https://api.example.com/auth/refresh", 50)
        panel.add(self.txt_endpoint, cc)

        cc.gridy = 2
        cc.gridwidth = 2
        cc.gridx = 0
        panel.add(JLabel("Injection Header Name:"), cc)
        cc.gridx = 2
        panel.add(JLabel("Injection Header Value (use {{token}}):"), cc)

        cc.gridy = 3
        cc.gridx = 0
        self.txt_inject_header_name = JTextField("Authorization")
        panel.add(self.txt_inject_header_name, cc)
        cc.gridx = 2
        self.txt_inject_header_value = JTextField("Bearer {{token}}")
        panel.add(self.txt_inject_header_value, cc)

        cc.gridy = 4
        cc.gridx = 0
        cc.gridwidth = 2
        self.chk_scope_only = JCheckBox("Only inject for in-scope hosts (comma-separated below, blank = all):", False)
        panel.add(self.chk_scope_only, cc)
        cc.gridx = 2
        self.txt_scope_hosts = JTextField("")
        panel.add(self.txt_scope_hosts, cc)

        return panel

    # --- Extraction Config ---

    def _build_extraction_config(self):
        panel = JPanel(GridBagLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Response Token Extraction"))
        ec = GridBagConstraints()
        ec.insets = Insets(2, 5, 2, 5)
        ec.anchor = GridBagConstraints.WEST
        ec.fill = GridBagConstraints.HORIZONTAL
        ec.weightx = 1.0

        # Mode selector
        ec.gridx = 0
        ec.gridy = 0
        ec.gridwidth = 1
        panel.add(JLabel("Extraction Mode:"), ec)
        ec.gridx = 1
        ec.gridwidth = 3
        self.cmb_extract_mode = JComboBox([self.MODE_JSON_PATH, self.MODE_REGEX, self.MODE_STRING_JSON])
        self.cmb_extract_mode.addActionListener(self._toggle_extraction_mode)
        panel.add(self.cmb_extract_mode, ec)

        # --- JSON Path fields (shared with String-JSON) ---
        ec.gridy = 1
        ec.gridx = 0
        ec.gridwidth = 1
        self.lbl_jp_access = JLabel("Access Token JSON Path:")
        panel.add(self.lbl_jp_access, ec)
        ec.gridx = 1
        self.txt_resp_access_name = JTextField("jwt.token")
        panel.add(self.txt_resp_access_name, ec)
        ec.gridx = 2
        self.lbl_jp_refresh = JLabel("Refresh Token JSON Path (Active only):")
        panel.add(self.lbl_jp_refresh, ec)
        ec.gridx = 3
        self.txt_resp_refresh_name = JTextField("jwt.refresh_token")
        panel.add(self.txt_resp_refresh_name, ec)

        # --- Regex fields ---
        ec.gridy = 2
        ec.gridx = 0
        ec.gridwidth = 4
        self.lbl_regex_help = JLabel(
            "<html><i>Use a capture group <b>()</b> around the token value. "
            "Example: <code>\"JWTToken\"\\s*:\\s*\"([^\"]+)\"</code></i></html>"
        )
        panel.add(self.lbl_regex_help, ec)

        ec.gridy = 3
        ec.gridx = 0
        ec.gridwidth = 1
        self.lbl_rx_access = JLabel("Access Token Regex:")
        panel.add(self.lbl_rx_access, ec)
        ec.gridx = 1
        ec.gridwidth = 3
        self.txt_regex_access = JTextField('"access_token"\\s*:\\s*"([^"]+)"')
        panel.add(self.txt_regex_access, ec)

        ec.gridy = 4
        ec.gridx = 0
        ec.gridwidth = 1
        self.lbl_rx_refresh = JLabel("Refresh Token Regex (Active only):")
        panel.add(self.lbl_rx_refresh, ec)
        ec.gridx = 1
        ec.gridwidth = 3
        self.txt_regex_refresh = JTextField('"refresh_token"\\s*:\\s*"([^"]+)"')
        panel.add(self.txt_regex_refresh, ec)

        # --- String-JSON help ---
        ec.gridy = 5
        ec.gridx = 0
        ec.gridwidth = 4
        self.lbl_str_json_help = JLabel(
            '<html><i>String-Escaped JSON: For responses like '
            '<code>"{\\\"key\\\":\\\"val\\\"}"</code>. '
            'Auto-unescapes first, then uses JSON Path above.</i></html>'
        )
        panel.add(self.lbl_str_json_help, ec)

        return panel

    # --- Active Mode Config ---

    def _build_active_config(self):
        panel = JPanel(GridBagLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Active Mode Configuration"))
        ac = GridBagConstraints()
        ac.insets = Insets(2, 5, 2, 5)
        ac.anchor = GridBagConstraints.WEST
        ac.fill = GridBagConstraints.HORIZONTAL
        ac.weightx = 1.0
        ac.gridwidth = 4

        # Refresh token input
        ac.gridx = 0
        ac.gridy = 0
        panel.add(JLabel("Initial Refresh Token (paste raw value, no quotes):"), ac)
        ac.gridy = 1
        ac.fill = GridBagConstraints.BOTH
        ac.weighty = 0.3
        self.txt_refresh_token = JTextArea(3, 50)
        self.txt_refresh_token.setLineWrap(True)
        panel.add(JScrollPane(self.txt_refresh_token), ac)
        ac.weighty = 0
        ac.fill = GridBagConstraints.HORIZONTAL

        # Custom headers & body
        ac.gridy = 2
        ac.gridwidth = 2
        ac.gridx = 0
        panel.add(JLabel("Custom Request Headers (Key: Value, one per line):"), ac)
        ac.gridx = 2
        panel.add(JLabel("Custom Body Parameters (key: value, one per line):"), ac)

        ac.gridy = 3
        ac.gridx = 0
        ac.fill = GridBagConstraints.BOTH
        ac.weighty = 0.5
        self.txt_custom_headers = JTextArea("", 4, 25)
        panel.add(JScrollPane(self.txt_custom_headers), ac)
        ac.gridx = 2
        self.txt_custom_body = JTextArea("", 4, 25)
        panel.add(JScrollPane(self.txt_custom_body), ac)
        ac.weighty = 0
        ac.fill = GridBagConstraints.HORIZONTAL

        # Options row
        ac.gridy = 4
        ac.gridx = 0
        ac.gridwidth = 4
        self.chk_add_client_time = JCheckBox("Add 'client_time: {{timestamp}}' to body", False)
        panel.add(self.chk_add_client_time, ac)

        # Request token names
        ac.gridy = 5
        ac.gridwidth = 1
        ac.gridx = 0
        panel.add(JLabel("Request Refresh Token Key:"), ac)
        ac.gridx = 1
        self.txt_req_refresh_name = JTextField("refresh_token")
        panel.add(self.txt_req_refresh_name, ac)

        # Auto-refresh trigger
        ac.gridx = 2
        panel.add(JLabel("Auto-Refresh Trigger (string in response):"), ac)
        ac.gridx = 3
        self.txt_trigger = JTextField("token is expired")
        panel.add(self.txt_trigger, ac)

        # --- Auto-Refresh Options ---
        ac.gridy = 6
        ac.gridx = 0
        ac.gridwidth = 4
        auto_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 2))
        auto_panel.setBorder(BorderFactory.createTitledBorder("Auto-Refresh Scheduling"))

        self.chk_auto_refresh_expiry = JCheckBox("Refresh before JWT expiry, buffer (seconds):", False)
        auto_panel.add(self.chk_auto_refresh_expiry)
        self.spn_expiry_buffer = JSpinner(SpinnerNumberModel(30, 5, 600, 5))
        auto_panel.add(self.spn_expiry_buffer)

        self.chk_auto_refresh_interval = JCheckBox("Fixed interval refresh every (minutes):", False)
        auto_panel.add(self.chk_auto_refresh_interval)
        self.spn_interval_minutes = JSpinner(SpinnerNumberModel(5, 1, 120, 1))
        auto_panel.add(self.spn_interval_minutes)

        panel.add(auto_panel, ac)

        return panel

    # --- Passive Mode Config ---

    def _build_passive_config(self):
        panel = JPanel(GridBagLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Passive Mode Configuration"))
        pc = GridBagConstraints()
        pc.insets = Insets(2, 5, 2, 5)
        pc.anchor = GridBagConstraints.WEST
        pc.fill = GridBagConstraints.HORIZONTAL
        pc.weightx = 1.0

        pc.gridx = 0
        pc.gridy = 0
        pc.gridwidth = 2
        panel.add(JLabel("Session Identifier Claims (one per line, blank = single-session mode):"), pc)

        pc.gridy = 1
        pc.fill = GridBagConstraints.BOTH
        self.txt_passive_id_claims = JTextArea("id\nchild_id", 4, 50)
        panel.add(JScrollPane(self.txt_passive_id_claims), pc)

        pc.gridy = 2
        pc.fill = GridBagConstraints.HORIZONTAL
        pc.gridwidth = 1
        self.btn_clear_cache = JButton("Clear Learned Tokens")
        self.btn_clear_cache.addActionListener(self._on_clear_cache)
        panel.add(self.btn_clear_cache, pc)

        # --- BAC Testing Sub-Panel ---
        pc.gridy = 3
        pc.gridwidth = 2
        pc.fill = GridBagConstraints.HORIZONTAL
        bac_panel = JPanel(GridBagLayout())
        bac_panel.setBorder(BorderFactory.createTitledBorder(
            "BAC Testing (Broken Access Control)"
        ))
        bc = GridBagConstraints()
        bc.insets = Insets(3, 5, 3, 5)
        bc.anchor = GridBagConstraints.WEST
        bc.fill = GridBagConstraints.HORIZONTAL
        bc.weightx = 1.0

        # Enable checkbox
        bc.gridx = 0
        bc.gridy = 0
        bc.gridwidth = 4
        self.chk_bac_enabled = JCheckBox(
            "Enable BAC Testing - Inject a different user's token into requests", False
        )
        bac_panel.add(self.chk_bac_enabled, bc)

        # Inject As dropdown
        bc.gridy = 1
        bc.gridwidth = 1
        bac_panel.add(JLabel("Inject As (session):"), bc)
        bc.gridx = 1
        bc.gridwidth = 2
        self.cmb_bac_inject_as = JComboBox()
        self.cmb_bac_inject_as.setPrototypeDisplayValue("session_placeholder_long_text_here")
        bac_panel.add(self.cmb_bac_inject_as, bc)
        bc.gridx = 3
        bc.gridwidth = 1
        self.btn_bac_refresh = JButton("Refresh Sessions")
        self.btn_bac_refresh.addActionListener(self._on_bac_refresh_sessions)
        bac_panel.add(self.btn_bac_refresh, bc)

        # Apply To radio group
        bc.gridy = 2
        bc.gridx = 0
        bc.gridwidth = 1
        bac_panel.add(JLabel("Apply To:"), bc)

        bc.gridx = 1
        self.radio_bac_repeater = JRadioButton(self.BAC_REPEATER_ONLY, True)
        bac_panel.add(self.radio_bac_repeater, bc)
        bc.gridx = 2
        self.radio_bac_all = JRadioButton(self.BAC_ALL_TOOLS, False)
        bac_panel.add(self.radio_bac_all, bc)
        bc.gridx = 3
        self.radio_bac_all_no_proxy = JRadioButton(self.BAC_ALL_EXCEPT_PROXY, False)
        bac_panel.add(self.radio_bac_all_no_proxy, bc)

        bac_apply_group = ButtonGroup()
        bac_apply_group.add(self.radio_bac_repeater)
        bac_apply_group.add(self.radio_bac_all)
        bac_apply_group.add(self.radio_bac_all_no_proxy)

        # Help text
        bc.gridy = 3
        bc.gridx = 0
        bc.gridwidth = 4
        bac_panel.add(JLabel(
            "<html><i>When enabled, ALL matching requests will have their token replaced "
            "with the selected session's token -- regardless of the original user.</i></html>"
        ), bc)

        # Learned Sessions display
        bc.gridy = 4
        bc.gridwidth = 4
        bac_panel.add(JLabel("Learned Sessions:"), bc)

        bc.gridy = 5
        bc.fill = GridBagConstraints.BOTH
        bc.weighty = 0.5
        self.txt_learned_sessions = JTextArea(4, 50)
        self.txt_learned_sessions.setEditable(False)
        self.txt_learned_sessions.setText("(No sessions learned yet. Browse the app through proxy to learn tokens.)")
        bac_panel.add(JScrollPane(self.txt_learned_sessions), bc)

        panel.add(bac_panel, pc)

        return panel

    # --- Log & Token Panel ---

    def _build_log_panel(self):
        panel = JPanel(GridBagLayout())
        panel.setBorder(BorderFactory.createTitledBorder("Log & Current Token"))
        lc = GridBagConstraints()
        lc.insets = Insets(2, 5, 2, 5)
        lc.fill = GridBagConstraints.HORIZONTAL
        lc.weightx = 0.5
        lc.weighty = 0

        lc.gridx = 0
        lc.gridy = 0
        self.lbl_log = JLabel("Log:")
        panel.add(self.lbl_log, lc)
        lc.gridx = 1
        self.lbl_current_token = JLabel("Current Access Token (Active Mode):")
        panel.add(self.lbl_current_token, lc)

        lc.gridy = 1
        lc.weighty = 1.0
        lc.fill = GridBagConstraints.BOTH
        lc.gridx = 0
        self.txt_log = JTextArea(15, 25)
        self.txt_log.setEditable(False)
        self.scroll_log = JScrollPane(self.txt_log)
        panel.add(self.scroll_log, lc)

        lc.gridx = 1
        self.txt_access_token = JTextArea(15, 25)
        self.txt_access_token.setEditable(False)
        self.txt_access_token.setLineWrap(True)
        self.txt_access_token.setWrapStyleWord(True)
        self.scroll_access_token = JScrollPane(self.txt_access_token)
        panel.add(self.scroll_access_token, lc)

        return panel

    # --- Transaction Panel ---

    def _build_transaction_panel(self):
        panel = JPanel(GridBagLayout())
        self.transaction_border = BorderFactory.createTitledBorder("Last Transaction")
        panel.setBorder(self.transaction_border)
        tc = GridBagConstraints()
        tc.insets = Insets(2, 5, 2, 5)
        tc.fill = GridBagConstraints.HORIZONTAL
        tc.weightx = 0.5
        tc.weighty = 0

        tc.gridx = 0
        tc.gridy = 0
        panel.add(JLabel("Last Request:"), tc)
        tc.gridx = 1
        panel.add(JLabel("Last Response:"), tc)

        tc.gridy = 1
        tc.weighty = 1.0
        tc.fill = GridBagConstraints.BOTH
        tc.gridx = 0
        self.txt_last_request = JTextArea(15, 25)
        self.txt_last_request.setEditable(False)
        panel.add(JScrollPane(self.txt_last_request), tc)

        tc.gridx = 1
        self.txt_last_response = JTextArea(15, 25)
        self.txt_last_response.setEditable(False)
        panel.add(JScrollPane(self.txt_last_response), tc)

        return panel

    # ===================================================================
    # UI TOGGLING
    # ===================================================================

    def _toggle_mode(self, event):
        is_active = self.radio_active_mode.isSelected()
        self.active_mode_panel.setVisible(is_active)
        self.passive_mode_panel.setVisible(not is_active)
        self.btn_refresh.setEnabled(is_active)
        self.lbl_current_token.setVisible(is_active)
        self.scroll_access_token.setVisible(is_active)
        self.transaction_panel.setVisible(is_active)

        if is_active:
            self.transaction_border.setTitle("Last Active Transaction")
            if event:
                self._log("[INFO] Switched to Active Mode.")
        else:
            self.transaction_border.setTitle("Last Passive Intercept")
            if event:
                self._log("[INFO] Switched to Passive Mode.")

        self.config_panel.revalidate()
        self.config_panel.repaint()
        self.transaction_panel.repaint()

    def _toggle_extraction_mode(self, event):
        mode = str(self.cmb_extract_mode.getSelectedItem())
        is_json = (mode == self.MODE_JSON_PATH)
        is_regex = (mode == self.MODE_REGEX)
        is_str_json = (mode == self.MODE_STRING_JSON)

        # JSON Path fields (visible for JSON Path AND String-Escaped JSON)
        for comp in [self.lbl_jp_access, self.txt_resp_access_name,
                     self.lbl_jp_refresh, self.txt_resp_refresh_name]:
            comp.setVisible(is_json or is_str_json)

        # Regex fields
        for comp in [self.lbl_regex_help, self.lbl_rx_access, self.txt_regex_access,
                     self.lbl_rx_refresh, self.txt_regex_refresh]:
            comp.setVisible(is_regex)

        # String-JSON help text
        self.lbl_str_json_help.setVisible(is_str_json)

        self.config_panel.revalidate()
        self.config_panel.repaint()

        if event:
            self._log("[INFO] Extraction mode changed to: " + mode)

    # ===================================================================
    # UI HELPERS
    # ===================================================================

    def _update_ui(self, component, text):
        SwingUtilities.invokeLater(lambda: component.setText(text))

    def _append_log_ui(self, message):
        SwingUtilities.invokeLater(lambda: self.txt_log.append(message + "\n"))

    def _log(self, message):
        ts = time.strftime("%H:%M:%S", time.localtime())
        full = "[{}] {}".format(ts, message)
        print(full)
        self._append_log_ui(full)

    # ===================================================================
    # TOKEN EXTRACTION (UNIFIED)
    # ===================================================================

    def _extract_token(self, response_body, key_or_pattern, mode=None):
        """
        Extract a token value from the response body using the configured mode.

        Args:
            response_body: The raw response body string.
            key_or_pattern: JSON path (for JSON/String-JSON) or regex (for Regex mode).
            mode: Override extraction mode, or None to use UI selection.

        Returns:
            The extracted token string, or None.
        """
        if not response_body or not key_or_pattern:
            return None

        if mode is None:
            mode = str(self.cmb_extract_mode.getSelectedItem())

        try:
            if mode == self.MODE_JSON_PATH:
                data = json.loads(response_body)
                return self._get_nested_key(data, key_or_pattern)

            elif mode == self.MODE_REGEX:
                match = re.search(key_or_pattern, response_body)
                if match:
                    return match.group(1) if match.lastindex else match.group(0)
                return None

            elif mode == self.MODE_STRING_JSON:
                # First parse: the response is a JSON string containing escaped JSON
                outer = json.loads(response_body)
                if isinstance(outer, basestring):
                    # Second parse: unescape to get the actual JSON object
                    inner = json.loads(outer)
                    return self._get_nested_key(inner, key_or_pattern)
                elif isinstance(outer, dict):
                    # Already a dict, use directly (graceful fallback)
                    return self._get_nested_key(outer, key_or_pattern)
                return None

        except Exception as e:
            self._log("[ERROR] Extraction failed ({}): {}".format(mode, str(e)))
            return None

    def _get_access_key_or_pattern(self):
        """Return the access token key/pattern based on extraction mode."""
        mode = str(self.cmb_extract_mode.getSelectedItem())
        if mode == self.MODE_REGEX:
            return self.txt_regex_access.getText()
        else:
            return self.txt_resp_access_name.getText()

    def _get_refresh_key_or_pattern(self):
        """Return the refresh token key/pattern based on extraction mode."""
        mode = str(self.cmb_extract_mode.getSelectedItem())
        if mode == self.MODE_REGEX:
            return self.txt_regex_refresh.getText()
        else:
            return self.txt_resp_refresh_name.getText()

    # ===================================================================
    # JWT UTILITIES
    # ===================================================================

    def _get_nested_key(self, data_dict, key_string):
        """Navigate a nested dict using dot notation (e.g., 'jwt.token')."""
        keys = key_string.split('.')
        current = data_dict
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current

    def _decode_jwt_payload(self, jwt_token):
        """Decode the payload portion of a JWT token."""
        try:
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return None
            payload_b64 = parts[1]
            # Add padding for Base64 URL-safe decoding
            payload_b64 += '=' * (-len(payload_b64) % 4)
            # Handle URL-safe base64 characters
            payload_b64 = payload_b64.replace('-', '+').replace('_', '/')
            decoded_bytes = Base64.getDecoder().decode(payload_b64)
            return json.loads(self._helpers.bytesToString(decoded_bytes))
        except Exception as e:
            self._log("[ERROR] Failed to decode JWT: " + str(e))
            return None

    def _get_jwt_expiry(self, jwt_token):
        """Extract the 'exp' claim from a JWT. Returns unix timestamp or 0."""
        payload = self._decode_jwt_payload(jwt_token)
        if payload and 'exp' in payload:
            try:
                return int(payload['exp'])
            except (ValueError, TypeError):
                pass
        return 0

    # ===================================================================
    # EVENT HANDLERS
    # ===================================================================

    def _on_refresh_click(self, event):
        self._log("[INFO] Manual refresh triggered.")
        Thread(lambda: self.refresh_tokens()).start()

    def _on_clear_cache(self, event):
        with self._cache_lock:
            self.token_cache = {}
        self._update_bac_dropdown()
        self._log("[PASSIVE] Token cache cleared.")

    # ===================================================================
    # ACTIVE MODE: TOKEN REFRESH
    # ===================================================================

    def refresh_tokens(self):
        """Perform an HTTP request to the token endpoint to get fresh tokens."""
        if not self.radio_active_mode.isSelected():
            self._log("[WARN] Refresh ignored: Not in Active Mode.")
            return

        if not self._refresh_lock.acquire(False):
            self._log("[INFO] Refresh already in progress. Skipping.")
            return

        self._update_ui(self.txt_last_request, "")
        self._update_ui(self.txt_last_response, "Preparing request...")

        conn = None
        try:
            endpoint_url_str = self.txt_endpoint.getText().strip()
            current_refresh_token = self.txt_refresh_token.getText().strip()
            req_refresh_name = self.txt_req_refresh_name.getText().strip()

            if not all([endpoint_url_str, current_refresh_token, req_refresh_name]):
                msg = "[ERROR] Active Mode requires: Endpoint URL, Refresh Token, and Request Token Key."
                self._log(msg)
                self._update_ui(self.txt_last_response, msg)
                return

            # Validate URL
            try:
                url = URL(endpoint_url_str)
            except Exception:
                msg = "[ERROR] Invalid endpoint URL: " + endpoint_url_str
                self._log(msg)
                self._update_ui(self.txt_last_response, msg)
                return

            self._log("[ACTIVE] Refreshing tokens via " + endpoint_url_str)

            # Build request body
            body_dict = {req_refresh_name: current_refresh_token}
            if self.chk_add_client_time.isSelected():
                body_dict['client_time'] = int(time.time())
            for line in self.txt_custom_body.getText().splitlines():
                if ':' in line:
                    key, val = line.split(':', 1)
                    key = key.strip()
                    val = val.strip()
                    if val == '{{timestamp}}':
                        val = int(time.time())
                    if key and key not in body_dict:
                        body_dict[key] = val
            request_body_str = json.dumps(body_dict)

            # Build headers
            headers_map = {"Content-Type": "application/json"}
            for line in self.txt_custom_headers.getText().splitlines():
                if ':' in line:
                    key, val = line.split(':', 1)
                    k = key.strip()
                    v = val.strip()
                    if k:
                        headers_map[k] = v

            # Open connection with timeouts
            conn = url.openConnection()
            conn.setRequestMethod("POST")
            conn.setDoOutput(True)
            conn.setConnectTimeout(10000)
            conn.setReadTimeout(15000)
            for key, value in headers_map.items():
                conn.setRequestProperty(key, value)

            # Display raw request
            raw_req = "POST {} HTTP/1.1\nHost: {}\n".format(url.getPath() or "/", url.getHost())
            for key, value in headers_map.items():
                raw_req += "{}: {}\n".format(key, value)
            raw_req += "\n" + request_body_str
            self._update_ui(self.txt_last_request, raw_req)

            # Send
            wr = OutputStreamWriter(conn.getOutputStream())
            wr.write(request_body_str)
            wr.flush()
            wr.close()

            # Read response
            response_code = conn.getResponseCode()
            self._log("[ACTIVE] Response status: " + str(response_code))

            stream = conn.getInputStream() if response_code < 400 else conn.getErrorStream()
            reader = BufferedReader(InputStreamReader(stream))
            response_body = "\n".join(iter(reader.readLine, None))
            reader.close()

            # Display raw response
            raw_resp = "HTTP/1.1 {} {}\n".format(response_code, conn.getResponseMessage() or "")
            header_fields = conn.getHeaderFields()
            if header_fields:
                for key in header_fields.keySet():
                    if key:
                        raw_resp += "{}: {}\n".format(key, header_fields.get(key).get(0))
            raw_resp += "\n" + response_body
            self._update_ui(self.txt_last_response, raw_resp)

            if response_code >= 400:
                self._log("[ERROR] Server returned error status: " + str(response_code))
                return

            self._parse_and_set_tokens(response_body)

        except Exception as e:
            msg = "[FATAL] Unhandled exception during refresh:\n" + str(e)
            self._log(msg)
            self._update_ui(self.txt_last_response, msg)
        finally:
            if conn:
                try:
                    conn.disconnect()
                except:
                    pass
            self._refresh_lock.release()

    def _parse_and_set_tokens(self, response_body):
        """Parse the response and update stored tokens."""
        try:
            if not response_body:
                self._log("[ERROR] Cannot parse tokens: empty response body.")
                return

            access_key = self._get_access_key_or_pattern()
            refresh_key = self._get_refresh_key_or_pattern()

            new_access = self._extract_token(response_body, access_key)
            new_refresh = self._extract_token(response_body, refresh_key)

            if not new_access:
                self._log("[ERROR] Access token not found in response.")
                self._log("[HINT] Check your extraction mode and key/pattern. Response preview:")
                preview = response_body[:200] + ("..." if len(response_body) > 200 else "")
                self._log("  " + preview)
                return

            with self._token_lock:
                self.active_access_token = new_access
                self._last_token_time = int(time.time())
                self._token_expiry = self._get_jwt_expiry(new_access)

            self._update_ui(self.txt_access_token, new_access)
            identity = self._jwt_identity_summary(new_access)
            self._log("[SUCCESS] New access token obtained.")
            self._log("  Identity: {}".format(identity))
            self._log("  Token:    {}".format(self._token_preview(new_access)))

            if self._token_expiry > 0:
                remaining = self._token_expiry - int(time.time())
                self._log("  Expires:  in {}s (~{} min)".format(remaining, remaining / 60))

            if new_refresh and self.radio_active_mode.isSelected():
                self._update_ui(self.txt_refresh_token, new_refresh)
                self._log("[INFO] New refresh token updated.")

        except Exception as e:
            self._log("[ERROR] Failed to parse response: " + str(e))

    # ===================================================================
    # HTTP LISTENER
    # ===================================================================

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.chk_enabled.isSelected():
            return

        if messageIsRequest:
            self._process_request(messageInfo, toolFlag)
        else:
            if self.radio_passive_mode.isSelected():
                self._handle_passive_response(messageInfo)
            elif self.radio_active_mode.isSelected():
                self._handle_active_response(messageInfo)

    # --- Request Processing ---

    def _process_request(self, messageInfo, toolFlag=0):
        # Check scope
        if self.chk_scope_only.isSelected():
            if not self._is_in_scope(messageInfo):
                return

        if self.radio_active_mode.isSelected():
            with self._token_lock:
                token = self.active_access_token
            if token:
                self._inject_token(messageInfo, token)

        elif self.radio_passive_mode.isSelected():

            # --- BAC Testing Mode ---
            if self.chk_bac_enabled.isSelected():
                if self._should_apply_bac(toolFlag):
                    selected = self.cmb_bac_inject_as.getSelectedItem()
                    if selected:
                        session_id = str(selected)
                        with self._cache_lock:
                            bac_token = self.token_cache.get(session_id)
                        if bac_token:
                            # Extract old token to show the swap
                            req_info = self._helpers.analyzeRequest(messageInfo)
                            old_token = self._extract_token_from_header(list(req_info.getHeaders()))
                            old_identity = self._jwt_identity_summary(old_token) if old_token else "(no token)"
                            new_identity = self._jwt_identity_summary(bac_token)
                            self._log("[BAC] {} | {} => {}".format(
                                self._tool_name(toolFlag), old_identity, new_identity
                            ))
                            self._log("  Old: {}".format(self._token_preview(old_token)))
                            self._log("  New: {}".format(self._token_preview(bac_token)))
                            self._inject_token(messageInfo, bac_token)
                return

            # --- Normal Passive Mode ---
            claims_list = self._get_claims_list()

            if claims_list:
                # Multi-session: find which session this request belongs to
                request_info = self._helpers.analyzeRequest(messageInfo)
                headers = list(request_info.getHeaders())
                old_token = self._extract_token_from_header(headers)

                if old_token:
                    payload = self._decode_jwt_payload(old_token)
                    composite_id = self._get_composite_id(payload, claims_list)

                    if composite_id:
                        with self._cache_lock:
                            new_token = self.token_cache.get(composite_id)

                        if new_token and new_token != old_token:
                            old_identity = self._jwt_identity_summary(old_token)
                            new_identity = self._jwt_identity_summary(new_token)
                            self._log("[PASSIVE] Refreshing token for: {} ({})".format(
                                composite_id, new_identity
                            ))
                            self._log("  Old: {}".format(self._token_preview(old_token)))
                            self._log("  New: {}".format(self._token_preview(new_token)))
                            self._inject_token(messageInfo, new_token)
            else:
                # Single-session: use the most recently learned token
                with self._token_lock:
                    token = self.active_access_token
                if token:
                    self._inject_token(messageInfo, token)

    # --- Response Processing ---

    def _handle_passive_response(self, messageInfo):
        """Learn tokens from observed responses in Passive Mode."""
        try:
            target_url = URL(self.txt_endpoint.getText().strip())
            request_info = self._helpers.analyzeRequest(
                messageInfo.getHttpService(), messageInfo.getRequest()
            )
            req_url = request_info.getUrl()

            if target_url.getHost() != req_url.getHost():
                return
            if target_url.getPath() != req_url.getPath():
                return

            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            status = response_info.getStatusCode()
            if not (200 <= status < 300):
                return

            self._log("[PASSIVE] Detected successful response from token endpoint (HTTP {}).".format(status))

            body_bytes = messageInfo.getResponse()[response_info.getBodyOffset():]
            body_str = self._helpers.bytesToString(body_bytes)

            access_key = self._get_access_key_or_pattern()
            new_access = self._extract_token(body_str, access_key)

            if not new_access:
                self._log("[PASSIVE] Could not extract access token from response.")
                return

            claims_list = self._get_claims_list()

            if claims_list:
                # Multi-session
                payload = self._decode_jwt_payload(new_access)
                composite_id = self._get_composite_id(payload, claims_list)
                if composite_id:
                    with self._cache_lock:
                        is_new = composite_id not in self.token_cache
                        self.token_cache[composite_id] = new_access
                    identity = self._jwt_identity_summary(new_access)
                    if is_new:
                        self._log("[PASSIVE] NEW session captured: {}".format(composite_id))
                    else:
                        self._log("[PASSIVE] Token refreshed for: {}".format(composite_id))
                    self._log("  Identity: {}".format(identity))
                    self._log("  Token:    {}".format(self._token_preview(new_access)))
                    self._update_bac_dropdown()
                else:
                    self._log("[PASSIVE] Could not build identifier from token claims.")
            else:
                # Single-session
                with self._token_lock:
                    self.active_access_token = new_access
                    self._last_token_time = int(time.time())
                    self._token_expiry = self._get_jwt_expiry(new_access)
                self._log("[PASSIVE] Stored latest token (single-session mode).")

        except Exception as e:
            self._log("[ERROR] Passive response handling failed: " + str(e))

    def _handle_active_response(self, messageInfo):
        """Check responses for trigger text and auto-refresh if found."""
        trigger_text = self.txt_trigger.getText().strip()
        if not trigger_text:
            return
        try:
            resp_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            body_bytes = messageInfo.getResponse()[resp_info.getBodyOffset():]
            body_str = self._helpers.bytesToString(body_bytes)
            if trigger_text in body_str:
                self._log("[AUTO-REFRESH] Trigger text '{}' found.".format(trigger_text))
                Thread(lambda: self.refresh_tokens()).start()
        except Exception as e:
            self._log("[ERROR] Active response check failed: " + str(e))

    # ===================================================================
    # TOKEN INJECTION
    # ===================================================================

    def _inject_token(self, messageInfo, access_token):
        """Inject the token into the request's headers."""
        header_name = self.txt_inject_header_name.getText().strip()
        value_format = self.txt_inject_header_value.getText().strip()
        if not header_name or not value_format:
            return

        final_value = value_format.replace('{{token}}', access_token)
        new_header = "{}: {}".format(header_name, final_value)

        request_info = self._helpers.analyzeRequest(messageInfo)
        headers = list(request_info.getHeaders())

        found = False
        for i, h in enumerate(headers):
            if h.lower().startswith(header_name.lower() + ":"):
                headers[i] = new_header
                found = True
                break
        if not found:
            headers.append(new_header)

        body = messageInfo.getRequest()[request_info.getBodyOffset():]
        messageInfo.setRequest(self._helpers.buildHttpMessage(headers, body))

    # ===================================================================
    # HELPERS
    # ===================================================================

    def _get_claims_list(self):
        """Get the list of non-empty claim names for passive session identification."""
        return [
            line.strip()
            for line in self.txt_passive_id_claims.getText().splitlines()
            if line.strip()
        ]

    def _get_composite_id(self, payload, claims_list):
        """Build a composite identifier string from JWT payload claims."""
        if not payload:
            return None
        parts = []
        for claim in claims_list:
            value = self._get_nested_key(payload, claim)
            if value is not None:
                parts.append(str(value))
        return "|".join(parts) if parts else None

    def _token_preview(self, token):
        """Return a short preview of a token string."""
        if not token:
            return "(none)"
        if len(token) > 40:
            return token[:20] + "..." + token[-15:]
        return token

    def _jwt_identity_summary(self, jwt_token):
        """
        Decode a JWT and return a human-readable summary of who it belongs to.
        Shows key identity claims like sub, email, username, role, etc.
        """
        if not jwt_token:
            return "(no token)"
        payload = self._decode_jwt_payload(jwt_token)
        if not payload:
            return "(non-JWT or invalid)"

        # Collect interesting identity claims
        identity_keys = [
            'sub', 'email', 'username', 'user_id', 'name',
            'preferred_username', 'role', 'roles', 'scope',
            'aud', 'azp', 'client_id', 'id', 'child_id'
        ]
        parts = []
        for key in identity_keys:
            if key in payload:
                val = payload[key]
                # Truncate long values
                val_str = str(val)
                if len(val_str) > 50:
                    val_str = val_str[:47] + "..."
                parts.append("{}={}".format(key, val_str))

        if parts:
            summary = ", ".join(parts)
        else:
            # Fallback: show first few claims
            all_keys = list(payload.keys())[:5]
            summary = "claims: [{}]".format(", ".join(all_keys))

        # Add expiry info
        if 'exp' in payload:
            try:
                exp = int(payload['exp'])
                remaining = exp - int(time.time())
                if remaining > 0:
                    summary += " (exp: {}s)".format(remaining)
                else:
                    summary += " (EXPIRED {}s ago)".format(abs(remaining))
            except:
                pass

        return summary

    def _extract_token_from_header(self, headers):
        """Extract the existing token from the injection header in request headers."""
        target = self.txt_inject_header_name.getText().strip().lower()
        for header in headers:
            if header.lower().startswith(target + ":"):
                value = header.split(":", 1)[1].strip()
                if value.lower().startswith("bearer "):
                    value = value[7:]
                return value
        return None

    def _is_in_scope(self, messageInfo):
        """Check if the request is in scope based on user-configured hosts."""
        try:
            hosts_str = self.txt_scope_hosts.getText().strip()
            if not hosts_str:
                # If no hosts specified, use Burp's scope
                return self._callbacks.isInScope(
                    self._helpers.analyzeRequest(messageInfo).getUrl()
                )
            # Check against user-specified hosts
            allowed = [h.strip().lower() for h in hosts_str.split(",") if h.strip()]
            service = messageInfo.getHttpService()
            return service.getHost().lower() in allowed
        except:
            return True  # Fail open

    def _should_apply_bac(self, toolFlag):
        """Check if BAC token swap should apply to this Burp tool."""
        if self.radio_bac_repeater.isSelected():
            return toolFlag == self.TOOL_REPEATER
        elif self.radio_bac_all.isSelected():
            return True
        elif self.radio_bac_all_no_proxy.isSelected():
            return toolFlag != self.TOOL_PROXY
        return False

    def _tool_name(self, toolFlag):
        """Return a human-readable name for a Burp tool flag."""
        names = {
            self.TOOL_PROXY: "Proxy",
            self.TOOL_SCANNER: "Scanner",
            self.TOOL_INTRUDER: "Intruder",
            self.TOOL_REPEATER: "Repeater",
            self.TOOL_EXTENDER: "Extender",
        }
        return names.get(toolFlag, "Tool-{}".format(toolFlag))

    def _update_bac_dropdown(self):
        """Refresh the BAC 'Inject As' dropdown and learned sessions display."""
        ext = self  # capture reference for closure

        def _update():
            # Remember current selection
            current = ext.cmb_bac_inject_as.getSelectedItem()
            ext.cmb_bac_inject_as.removeAllItems()

            with ext._cache_lock:
                session_ids = sorted(ext.token_cache.keys())

            if not session_ids:
                ext.txt_learned_sessions.setText(
                    "(No sessions learned yet. Browse the app through proxy to learn tokens.)"
                )
                return

            lines = []
            for sid in session_ids:
                ext.cmb_bac_inject_as.addItem(sid)
                with ext._cache_lock:
                    token = ext.token_cache.get(sid, "")

                # Decode JWT to show identity
                identity = ext._jwt_identity_summary(token)
                preview = ext._token_preview(token)
                lines.append("[{}]".format(sid))
                lines.append("  Identity: {}".format(identity))
                lines.append("  Token:    {}".format(preview))
                lines.append("")

            ext.txt_learned_sessions.setText("\n".join(lines))

            # Restore previous selection if still available
            if current:
                for i in range(ext.cmb_bac_inject_as.getItemCount()):
                    if str(ext.cmb_bac_inject_as.getItemAt(i)) == str(current):
                        ext.cmb_bac_inject_as.setSelectedIndex(i)
                        break

        SwingUtilities.invokeLater(_update)

    def _on_bac_refresh_sessions(self, event):
        """Manual refresh of the BAC sessions dropdown."""
        self._update_bac_dropdown()
        self._log("[BAC] Session list refreshed.")

    # ===================================================================
    # ITab INTERFACE
    # ===================================================================

    def getTabCaption(self):
        return "JWT Refresher"

    def getUiComponent(self):
        return self._main_panel
