# Burp Suite JWT Refresher
#
# This extension provides a UI to manage and automatically refresh JWT tokens.
# It uses two distinct modes for handling single or multiple user sessions.

# Jython/Java Swing imports for the UI
from javax.swing import JPanel, JLabel, JTextField, JTextArea, JScrollPane, JButton, JCheckBox, BorderFactory, SwingUtilities, JRadioButton, ButtonGroup
from java.awt import GridBagLayout, GridBagConstraints, Insets, FlowLayout
from java.net import URL, HttpURLConnection
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader
from java.lang import Thread
from java.util import Base64

# Burp-specific imports
from burp import IBurpExtender, ITab, IHttpListener

# Standard library imports
import json
import time
from threading import Lock

# Locks to ensure thread-safe operations.
token_lock = Lock()
refresh_lock = Lock()

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    """
    The main class for the Burp Suite extension.
    """

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JWT Refresher")
        
        # --- Data Model ---
        # For Active Mode (single session)
        self.active_access_token = None
        # For Passive Mode (multi-session)
        self.token_cache = {} # Maps composite identifier to latest access token
        
        self.build_ui()
        self.toggle_mode(None)
        
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        print "JWT Refresher extension loaded successfully."

    def build_ui(self):
        """Builds the graphical user interface for the extension's tab."""
        self._main_panel = JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.insets = Insets(5, 5, 5, 5)
        c.anchor = GridBagConstraints.NORTHWEST
        c.fill = GridBagConstraints.HORIZONTAL
        c.weightx = 1.0
        c.gridx = 0
        
        # --- Section 1: Operating Mode ---
        c.gridy = 0
        c.weighty = 0
        mode_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        mode_panel.setBorder(BorderFactory.createTitledBorder("1. Operating Mode"))
        self.radio_active_mode = JRadioButton("Active Mode (Single Session, Manual Refresh)", True)
        self.radio_active_mode.addActionListener(self.toggle_mode)
        self.radio_passive_mode = JRadioButton("Passive Mode (Auto-Learning)", False)
        self.radio_passive_mode.addActionListener(self.toggle_mode)
        mode_group = ButtonGroup()
        mode_group.add(self.radio_active_mode)
        mode_group.add(self.radio_passive_mode)
        mode_panel.add(self.radio_active_mode)
        mode_panel.add(self.radio_passive_mode)
        self._main_panel.add(mode_panel, c)

        # --- Section 2: Configuration ---
        c.gridy += 1
        self.config_panel = self.build_config_panel()
        self._main_panel.add(self.config_panel, c)

        # --- Controls ---
        c.gridy += 1
        controls_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        controls_panel.setBorder(BorderFactory.createTitledBorder("Controls"))
        self.btn_refresh = JButton("Get/Refresh Tokens (Active Mode)")
        self.btn_refresh.addActionListener(self.handle_refresh_button_click)
        self.chk_enabled = JCheckBox("Enable Token Handling", False)
        controls_panel.add(self.btn_refresh)
        controls_panel.add(self.chk_enabled)
        self._main_panel.add(controls_panel, c)

        # --- Log & Tokens ---
        c.gridy += 1; c.weighty = 1.0; c.fill = GridBagConstraints.BOTH
        self.log_token_panel = JPanel(GridBagLayout())
        self.log_token_panel.setBorder(BorderFactory.createTitledBorder("Log & Current Token"))
        ltc = GridBagConstraints(); ltc.insets = Insets(2, 5, 2, 5); ltc.fill = GridBagConstraints.HORIZONTAL; ltc.weightx = 0.5; ltc.weighty = 0
        
        ltc.gridx = 0; ltc.gridy = 0;
        self.lbl_log = JLabel("Log:")
        self.log_token_panel.add(self.lbl_log, ltc)
        ltc.gridx = 1
        self.lbl_access_token = JLabel("Current Access Token (Active Mode Only):")
        self.log_token_panel.add(self.lbl_access_token, ltc)

        ltc.gridy = 1; ltc.weighty = 1.0; ltc.fill = GridBagConstraints.BOTH
        ltc.gridx = 0
        self.txt_log = JTextArea(15, 25)
        self.txt_log.setEditable(False)
        self.scroll_log = JScrollPane(self.txt_log)
        self.log_token_panel.add(self.scroll_log, ltc)
        
        ltc.gridx = 1
        self.txt_access_token = JTextArea(15, 25)
        self.txt_access_token.setEditable(False); self.txt_access_token.setLineWrap(True); self.txt_access_token.setWrapStyleWord(True)
        self.scroll_access_token = JScrollPane(self.txt_access_token)
        self.log_token_panel.add(self.scroll_access_token, ltc)
        self._main_panel.add(self.log_token_panel, c)

        # --- Last Transaction ---
        c.gridy += 1; c.weighty = 1.0
        self.transaction_panel = JPanel(GridBagLayout())
        self.transaction_border = BorderFactory.createTitledBorder("Last Transaction")
        self.transaction_panel.setBorder(self.transaction_border)
        tc = GridBagConstraints(); tc.insets = Insets(2, 5, 2, 5); tc.fill = GridBagConstraints.HORIZONTAL; tc.weightx = 0.5; tc.weighty = 0
        
        tc.gridx = 0; tc.gridy = 0
        self.transaction_panel.add(JLabel("Last Request:"), tc)
        tc.gridx = 1
        self.transaction_panel.add(JLabel("Last Response:"), tc)

        tc.gridy = 1; tc.weighty = 1.0; tc.fill = GridBagConstraints.BOTH
        tc.gridx = 0
        self.txt_last_request = JTextArea(15, 25)
        self.txt_last_request.setEditable(False)
        self.transaction_panel.add(JScrollPane(self.txt_last_request), tc)
        
        tc.gridx = 1
        self.txt_last_response = JTextArea(15, 25)
        self.txt_last_response.setEditable(False)
        self.transaction_panel.add(JScrollPane(self.txt_last_response), tc)
        self._main_panel.add(self.transaction_panel, c)
        
    def build_config_panel(self):
        panel = JPanel(GridBagLayout())
        c = GridBagConstraints(); c.insets = Insets(2, 5, 2, 5); c.anchor = GridBagConstraints.WEST; c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1.0; c.gridx = 0
        
        # --- Common Configuration ---
        c.gridy = 0
        common_config_panel = JPanel(GridBagLayout())
        common_config_panel.setBorder(BorderFactory.createTitledBorder("Common Configuration"))
        cc = GridBagConstraints(); cc.insets = Insets(2, 5, 2, 5); cc.anchor = GridBagConstraints.WEST; cc.fill = GridBagConstraints.HORIZONTAL; cc.weightx = 1.0
        
        cc.gridx = 0; cc.gridy = 0; cc.gridwidth = 4
        common_config_panel.add(JLabel("Token Endpoint URL (to send to or listen for):"), cc)
        cc.gridy += 1
        self.txt_endpoint = JTextField("https://api.example.com/auth/refresh", 50)
        common_config_panel.add(self.txt_endpoint, cc)

        cc.gridy += 1; cc.gridwidth = 1; cc.gridx = 0
        common_config_panel.add(JLabel("Response Access Token Name:"), cc)
        cc.gridx = 1
        self.txt_resp_access_name = JTextField("jwt.token")
        common_config_panel.add(self.txt_resp_access_name, cc)
        
        cc.gridy += 1; cc.gridx = 0; cc.gridwidth = 4
        common_config_panel.add(JLabel("Injection Header Name:"), cc)
        cc.gridy += 1
        self.txt_inject_header_name = JTextField("X-Access-Token")
        common_config_panel.add(self.txt_inject_header_name, cc)
        
        cc.gridy += 1
        common_config_panel.add(JLabel("Injection Header Value Format (use {{token}}):"), cc)
        cc.gridy += 1
        self.txt_inject_header_value = JTextField("{{token}}")
        common_config_panel.add(self.txt_inject_header_value, cc)
        
        panel.add(common_config_panel, c)

        # --- Active Mode Panel ---
        c.gridy += 1
        self.active_mode_panel = JPanel(GridBagLayout())
        self.active_mode_panel.setBorder(BorderFactory.createTitledBorder("Active Mode Configuration"))
        ac = GridBagConstraints(); ac.insets = Insets(2, 5, 2, 5); ac.anchor = GridBagConstraints.WEST; ac.fill = GridBagConstraints.HORIZONTAL; ac.weightx = 1.0; ac.gridwidth = 4
        
        ac.gridy = 0
        self.active_mode_panel.add(JLabel("Initial Refresh Token (paste raw value, no quotes):"), ac)
        ac.gridy += 1; ac.fill = GridBagConstraints.BOTH; ac.weighty = 0.5
        self.txt_refresh_token = JTextArea(3, 50)
        self.txt_refresh_token.setLineWrap(True)
        self.active_mode_panel.add(JScrollPane(self.txt_refresh_token), ac)
        ac.weighty = 0; ac.fill = GridBagConstraints.HORIZONTAL

        ac.gridy += 1; ac.gridwidth = 2
        self.active_mode_panel.add(JLabel("Custom Headers (Key: Value format):"), ac)
        ac.gridx = 2
        self.active_mode_panel.add(JLabel("Custom Body Parameters (key: value format):"), ac)
        
        ac.gridy += 1; ac.gridx = 0; ac.fill = GridBagConstraints.BOTH; ac.weighty = 1.0
        self.txt_custom_headers = JTextArea("", 4, 25)
        self.active_mode_panel.add(JScrollPane(self.txt_custom_headers), ac)
        ac.gridx = 2
        self.txt_custom_body = JTextArea("", 4, 25)
        self.active_mode_panel.add(JScrollPane(self.txt_custom_body), ac)
        ac.weighty = 0; ac.fill = GridBagConstraints.HORIZONTAL
        
        ac.gridy += 1; ac.gridx = 0; ac.gridwidth = 4
        self.chk_add_client_time = JCheckBox("Automatically add 'client_time: {{timestamp}}' to body", False)
        self.active_mode_panel.add(self.chk_add_client_time, ac)

        ac.gridy += 1; ac.gridwidth = 1
        self.active_mode_panel.add(JLabel("Request Refresh Token Name:"), ac)
        ac.gridx = 1
        self.txt_req_refresh_name = JTextField("refresh_token")
        self.active_mode_panel.add(self.txt_req_refresh_name, ac)
        
        ac.gridx = 2
        self.active_mode_panel.add(JLabel("Response Refresh Token Name:"), ac)
        ac.gridx = 3
        self.txt_resp_refresh_name = JTextField("jwt.refresh_token")
        self.active_mode_panel.add(self.txt_resp_refresh_name, ac)

        ac.gridy += 1; ac.gridx = 0
        self.active_mode_panel.add(JLabel("Auto-Refresh Trigger (string in response):"), ac)
        ac.gridx = 1; ac.gridwidth = 3
        self.txt_trigger = JTextField("token is expired")
        self.active_mode_panel.add(self.txt_trigger, ac)
        
        panel.add(self.active_mode_panel, c)

        # --- Passive Mode Panel ---
        c.gridy += 2
        self.passive_mode_panel = JPanel(GridBagLayout())
        self.passive_mode_panel.setBorder(BorderFactory.createTitledBorder("Passive Mode Configuration"))
        pc = GridBagConstraints(); pc.insets = Insets(2, 5, 2, 5); pc.anchor = GridBagConstraints.WEST; pc.fill = GridBagConstraints.HORIZONTAL; pc.weightx = 1.0;
        
        pc.gridx = 0; pc.gridy = 0; pc.gridwidth = 2
        self.passive_mode_panel.add(JLabel("Session Identifier Claims (one per line). Leave blank for simple single-session mode."), pc)
        
        pc.gridy = 1; pc.fill = GridBagConstraints.BOTH
        self.txt_passive_identifier_claims = JTextArea("id\nchild_id", 4, 50)
        self.passive_mode_panel.add(JScrollPane(self.txt_passive_identifier_claims), pc)
        
        pc.gridy = 2; pc.fill = GridBagConstraints.HORIZONTAL; pc.gridwidth = 1
        self.btn_clear_cache = JButton("Clear Learned Tokens")
        self.btn_clear_cache.addActionListener(self.clear_token_cache)
        self.passive_mode_panel.add(self.btn_clear_cache, pc)
        
        panel.add(self.passive_mode_panel, c)
        
        return panel

    # --- Core Logic ---
    
    def toggle_mode(self, event):
        is_active = self.radio_active_mode.isSelected()
        self.active_mode_panel.setVisible(is_active)
        self.passive_mode_panel.setVisible(not is_active)
        self.btn_refresh.setEnabled(is_active)
        
        self.lbl_access_token.setVisible(is_active)
        self.scroll_access_token.setVisible(is_active)
        self.transaction_panel.setVisible(is_active)
        
        if is_active:
            self.transaction_border.setTitle("Last Active Transaction")
            if event: self.log("[INFO] Switched to Active Mode.")
        else:
            self.transaction_border.setTitle("Last Passive Intercept")
            if event: self.log("[INFO] Switched to Passive Mode.")
        self.transaction_panel.repaint()

    def _update_ui_text(self, component, text):
        SwingUtilities.invokeLater(lambda: component.setText(text))

    def _append_ui_log(self, message):
        SwingUtilities.invokeLater(lambda: self.txt_log.append(message + "\n"))

    def log(self, message):
        # FIXED: Add timestamp to all log messages
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        log_message = "[{}] {}".format(timestamp, message)
        print log_message
        self._append_ui_log(log_message)

    def handle_refresh_button_click(self, event):
        self.log("[INFO] Manual refresh triggered.")
        Thread(self.refresh_tokens).start()
    
    def clear_token_cache(self, event):
        self.token_cache = {}
        self.log("[PASSIVE] Token cache cleared. Ready to learn new sessions.")

    def get_nested_key(self, data_dict, key_string):
        keys = key_string.split('.'); current_level = data_dict
        for key in keys:
            if isinstance(current_level, dict) and key in current_level: current_level = current_level[key]
            else: return None
        return current_level

    def decode_jwt_payload(self, jwt_token):
        try:
            parts = jwt_token.split('.')
            if len(parts) != 3: return None
            payload_b64 = parts[1]
            payload_b64 += '=' * (-len(payload_b64) % 4)
            decoded_bytes = Base64.getDecoder().decode(payload_b64)
            return json.loads(self._helpers.bytesToString(decoded_bytes))
        except Exception as e:
            self.log("[ERROR] Failed to decode JWT: " + str(e))
            return None

    def refresh_tokens(self):
        if not self.radio_active_mode.isSelected():
            self.log("[WARN] Refresh ignored: Not in Active Mode.")
            return
        if not refresh_lock.acquire(False):
            self.log("[INFO] Refresh already in progress. Skipping.")
            return
        
        self._update_ui_text(self.txt_last_request, "")
        self._update_ui_text(self.txt_last_response, "Preparing request...")

        try:
            endpoint_url_str = self.txt_endpoint.getText()
            current_refresh_token = self.txt_refresh_token.getText().strip()
            req_refresh_name = self.txt_req_refresh_name.getText()

            if not all([endpoint_url_str, current_refresh_token, req_refresh_name]):
                error_msg = "[ERROR] Active Mode requires: Endpoint, Refresh Token, and Request Token Name."
                self.log(error_msg); self._update_ui_text(self.txt_last_response, error_msg)
                return

            self.log("[ACTIVE] Attempting to refresh tokens...")
            body_dict = {req_refresh_name: current_refresh_token}
            if self.chk_add_client_time.isSelected(): body_dict['client_time'] = int(time.time())
            for line in self.txt_custom_body.getText().splitlines():
                if ':' in line:
                    key, val = line.split(':', 1); key, val = key.strip(), val.strip()
                    if val == '{{timestamp}}': val = int(time.time())
                    if key not in body_dict: body_dict[key] = val
            request_body_str = json.dumps(body_dict)
            
            headers_map = {"Content-Type": "application/json"}
            for line in self.txt_custom_headers.getText().splitlines():
                if ':' in line:
                    key, val = line.split(':', 1); headers_map[key.strip()] = val.strip()
            
            url = URL(endpoint_url_str)
            conn = url.openConnection()
            conn.setRequestMethod("POST"); conn.setDoOutput(True)
            for key, value in headers_map.items(): conn.setRequestProperty(key, value)
            
            raw_request = "POST " + url.getPath() + " HTTP/1.1\nHost: " + url.getHost() + "\n"
            for key, value in headers_map.items(): raw_request += key + ": " + value + "\n"
            raw_request += "\n" + request_body_str
            self._update_ui_text(self.txt_last_request, raw_request)
            
            wr = OutputStreamWriter(conn.getOutputStream()); wr.write(request_body_str); wr.flush(); wr.close()
            
            response_code = conn.getResponseCode()
            self.log("[ACTIVE] Refresh endpoint responded with status: " + str(response_code))
            stream = conn.getInputStream() if response_code < 400 else conn.getErrorStream()
            reader = BufferedReader(InputStreamReader(stream))
            response_body = "".join(iter(reader.readLine, None)); reader.close()

            raw_response = "HTTP/1.1 " + str(response_code) + " " + conn.getResponseMessage() + "\n"
            header_fields = conn.getHeaderFields()
            for key in header_fields.keySet():
                if key: raw_response += key + ": " + header_fields.get(key).get(0) + "\n"
            raw_response += "\n" + response_body
            self._update_ui_text(self.txt_last_response, raw_response)

            if response_code >= 400: return
            self.parse_and_set_tokens(response_body)
        except Exception as e:
            error_msg = "[FATAL] An unhandled exception occurred during token refresh:\n\n" + str(e)
            self.log(error_msg); self._update_ui_text(self.txt_last_response, error_msg)
        finally:
            refresh_lock.release()

    def parse_and_set_tokens(self, response_body):
        try:
            if not response_body: self.log("[ERROR] Cannot parse tokens: Response body is empty."); return
            response_json = json.loads(response_body)
            new_access_token = self.get_nested_key(response_json, self.txt_resp_access_name.getText())
            new_refresh_token = self.get_nested_key(response_json, self.txt_resp_refresh_name.getText())

            if not new_access_token: self.log("[ERROR] Access token key not found in response."); return

            with token_lock: self.active_access_token = new_access_token
            self._update_ui_text(self.txt_access_token, self.active_access_token)
            self.log("[SUCCESS] New access token obtained.")

            if new_refresh_token and self.radio_active_mode.isSelected():
                self._update_ui_text(self.txt_refresh_token, new_refresh_token)
                self.log("[INFO] New refresh token also found and updated.")
        except Exception as e:
            self.log("[ERROR] Failed to parse JSON response: " + str(e))

    def get_composite_identifier(self, payload, claims_list):
        if not payload: return None
        identifier_parts = []
        for claim in claims_list:
            if claim:
                value = self.get_nested_key(payload, claim)
                identifier_parts.append(str(value))
        return "|".join(identifier_parts) if identifier_parts else None

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.chk_enabled.isSelected(): return
        
        if messageIsRequest:
            self.processRequest(messageInfo)
        else: # Is a response
            if self.radio_passive_mode.isSelected():
                self.handle_passive_response(messageInfo)
            elif self.radio_active_mode.isSelected():
                self.handle_active_response(messageInfo)

    def handle_passive_response(self, messageInfo):
        request_info = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
        try:
            target_url = URL(self.txt_endpoint.getText())
            if target_url.getHost() == request_info.getUrl().getHost() and target_url.getPath() == request_info.getUrl().getPath():
                response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
                if response_info.getStatusCode() / 100 == 2:
                    self.log("[PASSIVE] Detected successful response from token endpoint.")
                    response_body_bytes = messageInfo.getResponse()[response_info.getBodyOffset():]
                    response_body_str = self._helpers.bytesToString(response_body_bytes)
                    response_json = json.loads(response_body_str)
                    
                    new_access_token = self.get_nested_key(response_json, self.txt_resp_access_name.getText())
                    if new_access_token:
                        claims_list = [line for line in self.txt_passive_identifier_claims.getText().splitlines() if line.strip()]
                        # If claims are provided, use smart multi-session mode
                        if claims_list:
                            payload = self.decode_jwt_payload(new_access_token)
                            composite_id = self.get_composite_identifier(payload, claims_list)
                            if composite_id:
                                self.token_cache[composite_id] = new_access_token
                                self.log("[PASSIVE] Learned new token for identifier: " + composite_id)
                            else:
                                self.log("[PASSIVE] Could not build identifier from new token.")
                        # If no claims, use simple single-session mode
                        else:
                            self.log("[PASSIVE] No identifiers set. Storing latest token for single-session mode.")
                            with token_lock: self.active_access_token = new_access_token
        except Exception as e:
            self.log("[ERROR] Passive mode check failed: " + str(e))

    def handle_active_response(self, messageInfo):
        trigger_text = self.txt_trigger.getText()
        if not trigger_text: return
        response_body_bytes = messageInfo.getResponse()[self._helpers.analyzeResponse(messageInfo.getResponse()).getBodyOffset():]
        if self._helpers.bytesToString(response_body_bytes).find(trigger_text) > -1:
            self.log("[AUTO-REFRESH] Trigger text found in response.")
            Thread(self.refresh_tokens).start()

    def processRequest(self, messageInfo):
        if self.radio_active_mode.isSelected():
            with token_lock: token_to_inject = self.active_access_token
            if token_to_inject: self.inject_token(messageInfo, token_to_inject)
        elif self.radio_passive_mode.isSelected():
            claims_list = [line for line in self.txt_passive_identifier_claims.getText().splitlines() if line.strip()]
            # If claims are provided, use smart multi-session mode
            if claims_list:
                request_info = self._helpers.analyzeRequest(messageInfo)
                headers = list(request_info.getHeaders())
                old_token = None
                for header in headers:
                    if header.lower().startswith(self.txt_inject_header_name.getText().lower() + ":"):
                        old_token = header.split(":", 1)[1].strip()
                        if old_token.lower().startswith("bearer "): old_token = old_token[7:]
                        break
                
                if old_token:
                    payload = self.decode_jwt_payload(old_token)
                    composite_id = self.get_composite_identifier(payload, claims_list)
                    
                    if composite_id and composite_id in self.token_cache:
                        new_token = self.token_cache[composite_id]
                        if new_token != old_token:
                            self.log("[PASSIVE] Replacing token for identifier: " + composite_id)
                            self.log("          Old: " + old_token[:15] + "..." + old_token[-15:])
                            self.log("          New: " + new_token[:15] + "..." + new_token[-15:])
                            self.inject_token(messageInfo, new_token)
            # If no claims, use simple single-session mode
            else:
                with token_lock: token_to_inject = self.active_access_token
                if token_to_inject: self.inject_token(messageInfo, token_to_inject)

    def inject_token(self, messageInfo, access_token):
        inject_header_name = self.txt_inject_header_name.getText()
        inject_header_value_format = self.txt_inject_header_value.getText()
        if not inject_header_name or not inject_header_value_format: return

        final_header_value = inject_header_value_format.replace('{{token}}', access_token)
        new_header_line = inject_header_name + ": " + final_header_value
        
        request_info = self._helpers.analyzeRequest(messageInfo)
        headers = list(request_info.getHeaders())
        
        header_found = False
        for i, header in enumerate(headers):
            if header.lower().startswith(inject_header_name.lower() + ":"):
                headers[i] = new_header_line; header_found = True; break
        if not header_found: headers.append(new_header_line)

        body_bytes = messageInfo.getRequest()[request_info.getBodyOffset():]
        messageInfo.setRequest(self._helpers.buildHttpMessage(headers, body_bytes))

    def getTabCaption(self): return "JWT Refresher"
    def getUiComponent(self): return self._main_panel
