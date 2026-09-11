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