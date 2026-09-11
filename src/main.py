import json
import os
import re


class SecurityDataExtractor:

  def __init__(self):
    # 1. ALU Email Addresses (Staff, Alumni, SI subdomains)
    self.email_pattern = re.compile(
        r'\b[a-zA-Z0-9._%+-]+@(alueducation\.com|alumni\.alueducation\.com|si\.alueducation\.com)\b',
        re.IGNORECASE,
    )

    # 2. Credit Card Numbers (13-19 digits with spaces or dashes)
    self.card_pattern = re.compile(r'\b(?:\d[ -]*?){13,19}\b')

    # 3. URLs (http://, https://, or www.)
    self.url_pattern = re.compile(
        r'\b(?:https?://|www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b',
        re.IGNORECASE,
    )

    # 4. International Phone Numbers (+ followed by country code, spaces, dashes)
    self.phone_pattern = re.compile(
        r'\+(?:[0-9]{1,3})[ -]?\(?[0-9]{1,4}\)?[ -]?[0-9]{2,4}[ -]?[0-9]{3,4}\b'
    )

  def is_valid_luhn(self, card_str: str) -> bool:
    """Validates credit card numbers using the Luhn Algorithm (Mod 10)."""
    digits = [int(char) for char in re.sub(r'\D', '', card_str)]
    if not digits or len(digits) < 13:
      return False

    checksum = 0
    reversed_digits = digits[::-1]

    for index, digit in enumerate(reversed_digits):
      if index % 2 == 1:
        doubled = digit * 2
        checksum += doubled - 9 if doubled > 9 else doubled
      else:
        checksum += digit

    return checksum % 10 == 0

  def mask_credit_card(self, card_str: str) -> str:
    """Masks credit card numbers so only the last four digits remain visible."""
    clean_digits = re.sub(r'\D', '', card_str)
    return f'****-****-****-{clean_digits[-4:]}'

  def mask_email(self, email_str: str) -> str:
    """Masks email usernames to protect personal data (e.g., a****e@alueducation.com)."""
    username, domain = email_str.split('@')
    if len(username) <= 2:
      masked_user = username[0] + '*'
    else:
      masked_user = username[0] + '*' * (len(username) - 2) + username[-1]
    return f'{masked_user}@{domain}'

  def sanitize_input(self, text: str) -> str:
    """Strips HTML and Script tags to prevent injection risks."""
    return re.sub(r'<[^>]*>', '', text)

  def process_data(self, raw_text: str) -> dict:
    """Pre-processes text, extracts matched data, and applies security masking."""
    clean_text = self.sanitize_input(raw_text)

    # Extract & Validate Credit Cards
    raw_cards = self.card_pattern.findall(clean_text)
    valid_cards = [
        self.mask_credit_card(card)
        for card in raw_cards
        if self.is_valid_luhn(card)
    ]

    # Extract URLs
    urls = list(set(self.url_pattern.findall(clean_text)))

    # Extract International Phone Numbers
    phones = list(set(self.phone_pattern.findall(clean_text)))

    # Extract & Mask ALU Emails
    raw_emails = set(
        match.group(0) for match in self.email_pattern.finditer(clean_text)
    )
    masked_emails = [self.mask_email(email) for email in raw_emails]

    return {
        'alu_emails': masked_emails,
        'masked_credit_cards': valid_cards,
        'urls': urls,
        'phone_numbers': phones,
    }


def main():
  # Dynamically resolve paths relative to main.py position
  script_dir = os.path.dirname(os.path.abspath(__file__))
  project_root = os.path.abspath(os.path.join(script_dir, '..'))

  input_file = os.path.join(project_root, 'input', 'raw-text.txt')
  output_file = os.path.join(project_root, 'output', 'sample-output.json')

  try:
    with open(input_file, 'r', encoding='utf-8') as f:
      raw_data = f.read()
  except FileNotFoundError:
    print(f'Error: Could not find file at {input_file}')
    return

  extractor = SecurityDataExtractor()
  results = extractor.process_data(raw_data)

  os.makedirs(os.path.dirname(output_file), exist_ok=True)
  with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(results, f, indent=4)

  print('Data Extraction Complete. Sample Output:\n')
  print(json.dumps(results, indent=2))


if __name__ == '__main__':
  main()