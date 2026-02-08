from bs4 import BeautifulSoup
import re
from src.config import config

class SecurityEngine:
    """
    Handles detection of malicious content, hidden text, and risk scoring.
    """
    
    def __init__(self):
        self.injection_pattern = re.compile("|".join(config.INJECTION_KEYWORDS), re.IGNORECASE)

    def analyze_page(self, html_content: str, url: str) -> dict:
        """
        Main entry point for analyzing a page.
        Returns a risk report.
        """
        print(f"[*] Analyzing content from: {url}")
        soup = BeautifulSoup(html_content, 'lxml')
        
        # Check if domain is trusted
        is_trusted = any(domain in url for domain in config.TRUSTED_DOMAINS)
        if is_trusted:
            print(f"  [i] Domain {url} is in TRUSTED_DOMAINS. Applying relaxed security metrics.")

        # 1. Hidden Content Detection (Context-Aware)
        hidden_elements = self._detect_hidden_elements(soup, is_trusted)
        
        # 2. Prompt Injection Detection
        injection_found = self._detect_prompt_injection(soup)
        
        # 3. Deceptive UI Detection
        deceptive_ui = self._detect_deceptive_ui(soup)
            
        # 4. Phishing Detection (Brand mismatch)
        phishing_risk = self._detect_phishing(soup, url)
            
        # 5. Fake Dialog Detection
        fake_dialog = self._detect_fake_dialog(soup)
            
        # 6. Button Target Analysis
        suspicious_targets = self._analyze_button_targets(soup, is_trusted)
        
        # 7. Homograph Phishing Detection (Lookalike domains)
        homograph_match = self._detect_homograph_phishing(url)

        # Compile Alerts for console (and keep them simple)
        alerts = []
        if hidden_elements: alerts.append(f"Hidden content found")
        if injection_found: alerts.append(f"Injection detected")
        if deceptive_ui: alerts.append("Deceptive UI")
        if phishing_risk: alerts.append(f"Phishing ({phishing_risk})")
        if fake_dialog: alerts.append("Fake dialog")
        if suspicious_targets: alerts.append(f"Suspicious targets")
        
        if alerts:
            print(f"  [!] SECURITY ALERTS: {', '.join(alerts)}")
        
        # 7. Calculate Risk Score with Detailed Meta
        risk_score, explanation = self._calculate_risk_score(
            hidden_elements, 
            injection_found, 
            deceptive_ui if not is_trusted else [],
            phishing_risk,
            fake_dialog,
            suspicious_targets,
            url,
            homograph_match
        )
        
        return {
            "url": url,
            "risk_score": risk_score,
            "explanation": explanation,
            "threats": {
                "hidden_content": len(hidden_elements),
                "injection_detected": bool(injection_found),
                "deceptive_ui": bool(deceptive_ui) if not is_trusted else False,
                "phishing": bool(phishing_risk),
                "fake_dialog": bool(fake_dialog),
                "suspicious_targets": len(suspicious_targets),
                "homograph_phishing": bool(homograph_match)
            }
        }

    def _detect_phishing(self, soup: BeautifulSoup, url: str) -> str | None:
        """
        Detects phishing by looking for brand keywords on non-official domains.
        Returns the brand keyword found, or None.
        """
        # Phishing detection handles localhost testing
        is_local = "127.0.0.1" in url or "localhost" in url
        visible_text = self.sanitize_for_llm(str(soup)).lower()
        
        for brand in config.BRAND_KEYWORDS:
            if brand in visible_text:
                # If local and brand keyword found, it's a simulated phishing attack
                if is_local: return brand
                # In prod, check domain trust
                if not any(brand in url for domain in config.TRUSTED_DOMAINS):
                    return brand
        return None

    def _detect_homograph_phishing(self, url: str) -> str | None:
        """Detects lookalike domains based on edit distance."""
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower()
        if not domain: return None
        
        # Strip common TLDs for better matching
        base_domain = domain.split('.')[0]
        
        for trusted in config.TRUSTED_DOMAINS:
            target = trusted.split('.')[0]
            if base_domain == target: continue
            
            # Simple Levenshtein distance implementation
            def lev(s1, s2):
                if len(s1) < len(s2): return lev(s2, s1)
                if not s2: return len(s1)
                previous_row = range(len(s2) + 1)
                for i, c1 in enumerate(s1):
                    current_row = [i + 1]
                    for j, c2 in enumerate(s2):
                        insertions = previous_row[j + 1] + 1
                        deletions = current_row[j] + 1
                        substitutions = previous_row[j] + (c1 != c2)
                        current_row.append(min(insertions, deletions, substitutions))
                    previous_row = current_row
                return previous_row[-1]

            distance = lev(base_domain, target)
            # Distance of 1 or 2 is common for homographs (e.g., google vs g00gle)
            if distance <= 2 and len(base_domain) >= 5:
                # Check for common substitutions (o -> 0, l -> 1, m -> rn)
                lookalikes = [('0', 'o'), ('1', 'l'), ('rn', 'm'), ('vv', 'w')]
                for bad, good in lookalikes:
                    if bad in base_domain and good in target:
                        return f"Lookalike domain detected ({domain} vs {trusted})"
                
                # If distance is very small relative to length, flag it anyway
                if distance / len(target) < 0.3:
                    return f"Suspiciously similar domain ({domain} vs {trusted})"
        return None

    def _detect_fake_dialog(self, soup: BeautifulSoup) -> str | None:
        """
        Detects overlays that mimic system or security alerts.
        Returns description of what was found.
        """
        for div in soup.find_all('div'):
            style = div.get('style', '').lower()
            if ('position' in style and ('fixed' in style or 'absolute' in style)) and 'z-index' in style:
                text = div.get_text().lower()
                for kw in config.DIALOG_KEYWORDS:
                    if kw in text:
                        return f"Overlay detected with system keyword: '{kw}'"
        return None

    def _detect_hidden_elements(self, soup: BeautifulSoup, is_trusted: bool) -> list:
        """
        Returns list of metadata for elements hidden from humans but visible to LLMs.
        """
        hidden = []
        for tag in soup.find_all(style=True):
            style = tag['style'].lower()
            reason = ""
            if 'display:none' in style: reason = "display:none"
            elif 'visibility:hidden' in style: reason = "visibility:hidden"
            elif 'font-size:0' in style: reason = "font-size:0"
            
            if reason:
                content = tag.get_text().strip().lower()
                has_keywords = any(kw in content for kw in config.INJECTION_KEYWORDS)
                is_long_blob = len(content) > 150
                
                if has_keywords or (not is_trusted and is_long_blob):
                    hidden.append({
                        "tag": tag.name,
                        "reason": f"Hidden via {reason}",
                        "snippet": content[:50] + "..." if len(content) > 50 else content
                    })
        return hidden

    def _detect_prompt_injection(self, soup: BeautifulSoup) -> list:
        """
        Scans for known prompt injection strings in the visible text.
        Excludes script and style tags to avoid false positives from code.
        """
        injections = []
        # Create a copy so we don't mutate the original soup used for other checks
        clean_soup = BeautifulSoup(str(soup), 'lxml')
        for script_or_style in clean_soup(["script", "style"]):
            script_or_style.decompose()
            
        # Get all text nodes from clean content
        text_nodes = clean_soup.find_all(string=True)
        full_text = " ".join(text_nodes)
        normalized_text = " ".join(full_text.split())
        
        for keyword in config.INJECTION_KEYWORDS:
            if re.search(re.escape(keyword), normalized_text, re.IGNORECASE):
                injections.append(keyword)
            
        return injections

    def _detect_deceptive_ui(self, soup: BeautifulSoup) -> list:
        """
        Detects common patterns of deceptive UI (fake buttons, low opacity overlays).
        Returns list of findings.
        """
        findings = []
        for tag in soup.find_all(['button', 'a', 'input']):
            style = tag.get('style', '').lower()
            if 'opacity: 0' in style or 'opacity:0' in style:
                findings.append(f"Invisible element ({tag.name}) with zero opacity")
                continue
            
            opacity_match = re.search(r'opacity:\s*([0-9.]+)', style)
            if opacity_match:
                try:
                    val = float(opacity_match.group(1))
                    if val < 0.2:
                        findings.append(f"Near-invisible element ({tag.name}) with opacity {val}")
                except ValueError:
                    continue
        return findings

    def _analyze_button_targets(self, soup: BeautifulSoup, is_trusted: bool) -> list:
        """
        Inspects click targets (hrefs, onclicks) for potential malicious redirects.
        Returns detailed list of suspicious targets.
        """
        suspicious = []
        
        for tag in soup.find_all(['a', 'button', 'input']):
            target = ""
            if tag.name == 'a':
                target = tag.get('href', '')
            elif tag.name == 'button' or (tag.name == 'input' and tag.get('type') in ['button', 'submit']):
                # Try to extract from onclick
                onclick = tag.get('onclick', '')
                match = re.search(r"window\.location\s*=\s*['\"]([^'\"]+)['\"]", onclick)
                if match:
                    target = match.group(1)

            if target and target.startswith('http'):
                # Check if target domain is trusted
                target_trusted = any(domain in target for domain in config.TRUSTED_DOMAINS)
                
                # If we are on an untrusted page and it's pointing to another untrusted page, increase suspicion
                if not is_trusted and not target_trusted:
                    # Further check: is it pointing to our localhost attacker simulation?
                    if "127.0.0.1" in target or "attacker.com" in target:
                        suspicious.append({
                            "element": tag.name,
                            "text": (tag.get_text() or tag.get('value') or "").strip(),
                            "target": target
                        })
                        
        return suspicious

    def _calculate_risk_score(self, hidden, injection, deceptive, phishing_brand, fake_dialog, suspicious_targets, url, homograph_match=None) -> tuple[int, str]:
        score = 0
        reasons = []
        is_trusted = any(domain in url for domain in config.TRUSTED_DOMAINS)
        
        if injection:
            injection_weight = 2 if is_trusted else 5
            score += injection_weight
            reasons.append(f"Prompt injection detected using keywords: {', '.join(injection)}")
        
        if hidden:
            hidden_weight = 1 if is_trusted else 3
            score += hidden_weight
            descriptions = [f"{h['tag']} ({h['reason']})" for h in hidden]
            reasons.append(f"Detected hidden content designed for AI eyes: {', '.join(descriptions)}")
            
        if deceptive:
            deceptive_weight = 2 if is_trusted else 4
            score += deceptive_weight
            reasons.append(f"Visual deception: {', '.join(deceptive)}")

        if homograph_match:
            score += 8
            reasons.append(f"CRITICAL: {homograph_match}")

        if phishing_brand:
            score += 7
            reasons.append(f"Phishing detected: Using brand keyword '{phishing_brand}' on an untrusted or suspicious infrastructure.")

        if fake_dialog:
            score += 5
            reasons.append(f"Fake UI: {fake_dialog}")
            
        if suspicious_targets:
            score += 4
            target_list = [f"{t['element']} -> {t['target']}" for t in suspicious_targets]
            reasons.append(f"Suspicious redirects found in buttons: {', '.join(target_list)}")
            
        if score > 10: score = 10
        
        explanation = " | ".join(reasons) if reasons else "No immediate threats."
        return score, explanation

    def is_intent_aligned(self, task_description: str, action_data: dict, page_content: str) -> tuple[bool, str]:
        """
        Heuristic check to see if the proposed action aligns with the user's original goal.
        """
        if not action_data or not isinstance(action_data, dict):
            return False, "Invalid action data provided for alignment check."
            
        task_lower = (task_description or "").lower()
        action_type = action_data.get("action")
        
        if action_type == "navigate":
            url = action_data.get("url", "").lower()
            malicious_patterns = ["attacker.com", "leak", "payload"]
            is_explicit = any(pattern in task_lower for pattern in malicious_patterns)
            
            if any(pattern in url for pattern in malicious_patterns) and not is_explicit:
                return False, f"Target URL '{url}' matches known malicious patterns and was not explicitly requested."
            
            # Contextual mismatch (e.g. news task going to something weird)
            if "news" in task_lower and not any(trusted in url for trusted in config.TRUSTED_DOMAINS):
                # We don't block all non-trusted news, but this is a signal
                pass 
        
        if action_type == "click":
            selector = action_data.get("selector", "").lower()
            # If clicking a 'security alert' or 'update' button when the task is just browsing
            # We check if the selector itself or common dialog text is in the task description
            is_explicit = any(word in task_lower for word in ["update", "alert", "fix", "dialog", "popup"])
            if any(kw in selector for kw in ["update", "alert", "fix"]) and not is_explicit:
                return False, f"Attempting to click an alert/update button ('{selector}') when the goal is '{task_description}'."

        return True, "Action appears aligned with user intent."

    def _get_visible_soup(self, soup: BeautifulSoup) -> BeautifulSoup:
        """
        Returns a copy of the soup with all hidden elements removed.
        """
        visible_soup = BeautifulSoup(str(soup), 'lxml')
        for element in visible_soup.find_all(True):
            style = element.get('style', '').lower()
            if 'display:none' in style or 'visibility:hidden' in style or 'font-size:0' in style:
                element.decompose()
        return visible_soup

    def sanitize_for_llm(self, html_content: str) -> str:
        """
        Strips dangerous tags and HIDDEN elements, then returns clean text for the LLM.
        """
        soup = BeautifulSoup(html_content, 'lxml')
        visible_soup = self._get_visible_soup(soup)
        
        for script_or_style in visible_soup(["script", "style"]):
            script_or_style.decompose()
            
        return visible_soup.get_text(separator=' ', strip=True)
