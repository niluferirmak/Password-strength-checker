import re
import requests
import hashlib

class PasswordStrengthChecker:
    SPECIAL_CHAR_PATTERN = re.compile(r'[!@#$%^&*(),.?":{}|<>]')
    UPPERCASE_PATTERN = re.compile(r'[A-Z]')
    LOWERCASE_PATTERN = re.compile(r'[a-z]')
    DIGIT_PATTERN = re.compile(r'\d')

    def __init__(self, password: str):
        self.password = password

    def is_long_enough(self):
        return len(self.password) >= 8

    def has_uppercase(self):
        return bool(self.UPPERCASE_PATTERN.search(self.password))

    def has_lowercase(self):
        return bool(self.LOWERCASE_PATTERN.search(self.password))

    def has_digit(self):
        return bool(self.DIGIT_PATTERN.search(self.password))

    def has_special_char(self):
        return bool(self.SPECIAL_CHAR_PATTERN.search(self.password))

    def is_not_common(self):
        # Use k-Anonymity model from HaveIBeenPwned Pwned Passwords API
        sha1 = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if response.status_code != 200:
                return True  # Fail-safe: assume not common if API fails
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash_suffix, count in hashes:
                if hash_suffix == suffix:
                    return False  # Found in breached passwords
            return True
        except Exception:
            return True  # Fail-safe: assume not common if API fails

    def check_strength(self):
        checks = [
            (self.is_long_enough, "At least 8 characters long"),
            (self.has_uppercase, "Contains an uppercase letter"),
            (self.has_lowercase, "Contains a lowercase letter"),
            (self.has_digit, "Contains a number"),
            (self.has_special_char, "Contains a special character"),
            (self.is_not_common, "Not found in known data breaches")
        ]
        results = []
        all_passed = True
        for check, description in checks:
            if check():
                results.append(f"[✔] {description}")
            else:
                results.append(f"[✖] {description}")
                all_passed = False
        summary = "\n STRONG: Password meets all criteria." if all_passed else "\n WEAK: Please address the following issues:"
        return f"{summary}\n" + "\n".join(results)

def main():
    password = input("Enter a password to check its strength: ")
    checker = PasswordStrengthChecker(password)
    result = checker.check_strength()
    print(result)

if __name__ == "__main__":
    main()