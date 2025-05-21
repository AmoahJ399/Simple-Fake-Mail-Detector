import re

class FakeMailDetector:
    def __init__(self):
        # Very basic keywords for demonstration.
        # Real systems use far more sophisticated features.
        self.phishing_keywords = [
            "urgent action required", "verify your account", "security alert",
            "suspicious activity", "password reset link", "click here",
            "winnings", "prize", "unclaimed", "limited time offer",
            "invoice attached", "payment failed", "account locked"
        ]
        self.suspicious_domains = [
            "paypal.secure.com", "amazon.login.net", "bankofamerica.online.info"
            # These are illustrative. Real phishing domains are often complex.
        ]
        self.common_safe_domains = [
            "google.com", "microsoft.com", "amazon.com", "paypal.com",
            # Add more legitimate domains
        ]

    def _extract_domain(self, email_address):
        """Extracts the domain from an email address."""
        match = re.search(r"@([a-zA-Z0-9.-]+)", email_address)
        if match:
            return match.group(1).lower()
        return None

    def detect(self, sender_email, subject, body):
        is_suspicious = False
        reasons = []

        # 1. Check sender's domain
        sender_domain = self._extract_domain(sender_email)
        if sender_domain:
            if sender_domain in self.suspicious_domains:
                is_suspicious = True
                reasons.append(f"Suspicious sender domain: {sender_domain}")
            elif sender_domain not in self.common_safe_domains and '.' not in sender_domain:
                # Very basic check for malformed or uncommon domains
                is_suspicious = True
                reasons.append(f"Uncommon or potentially malformed sender domain: {sender_domain}")
        else:
            is_suspicious = True
            reasons.append("Could not extract sender domain.")


        # 2. Check for suspicious keywords in subject and body
        text_to_check = (subject + " " + body).lower()
        for keyword in self.phishing_keywords:
            if keyword in text_to_check:
                is_suspicious = True
                reasons.append(f"Contains suspicious keyword: '{keyword}'")

        # 3. Check for specific patterns (e.g., "click here" with non-matching link - more complex for this simple code)
        # For a truly simple example, we'll just flag the text itself.
        if "click here" in body.lower() and "http" not in body.lower():
             is_suspicious = True
             reasons.append("'Click here' without a visible URL (requires more advanced parsing for accuracy).")


        if is_suspicious:
            print(f"\n--- MAIL FLAGGED AS POTENTIALLY FAKE/PHISHING ---")
            print(f"Sender: {sender_email}")
            print(f"Subject: {subject}")
            print(f"Reasons: {', '.join(reasons)}")
            return True
        else:
            print(f"\n--- MAIL APPEARS LEGITIMATE (based on simple checks) ---")
            print(f"Sender: {sender_email}")
            print(f"Subject: {subject}")
            return False

# --- How to use it ---
if __name__ == "__main__":
    detector = FakeMailDetector()

    print("--- Testing Fake Mail Detector ---")

    # Example 1: Potentially fake
    detector.detect(
        sender_email="support@paypal.secure.com",
        subject="Urgent: Your account has been suspended!",
        body="Dear customer, your PayPal account has been temporarily suspended due to suspicious activity. Please click here to verify your account immediately to avoid permanent closure. Thank you."
    )

    # Example 2: More likely legitimate
    detector.detect(
        sender_email="noreply@google.com",
        subject="Your monthly security report",
        body="Dear user, here is your monthly Google security report. No unusual activity detected. Thank you."
    )

    # Example 3: Another potentially fake
    detector.detect(
        sender_email="info@winninglotto.info",
        subject="Congratulations! You've won!",
        body="You have an unclaimed prize of $1,000,000. Provide your bank details immediately to claim your winnings."
    )

    # Example 4: Testing an uncommon domain
    detector.detect(
        sender_email="admin@my-unknown-service.xyz",
        subject="Important Update",
        body="Please review our new terms and conditions."
    )