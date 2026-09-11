
A Python script that reads messy, untrusted text logs and pulls out specific pieces of information from them — like emails, URLs, phone numbers, and credit card numbers — while making sure nothing unsafe or sensitive slips through into the output.



(a) Project Structure

```text
alu-regex-data-extraction/
├── input/
│   └── raw-text.txt         # The raw, untrusted text you're feeding in
├── output/
│   └── sample-output.json   # The cleaned-up, masked results
├── src/
│   └── main.py               # The actual script
└── README.md                 # This file
```

---

(b) What Gets Extracted

 Data Type , How It's Found & Protected , Example Output 

 1.ALU Email Addresses;
  Matches emails ending in `@alueducation.com`, `@alumni.alueducation.com`, or `@si.alueducation.com`. The part before the `@` is partly hidden.  `"a**********e@alueducation.com"` 
 2.Credit Card Numbers;
 Looks for 13–19 digit sequences, checks them with the Luhn Algorithm, and only keeps the last 4 digits visible. `"****-****-****-1881"` 
 3.URLs;
  Picks up links starting with `http://`, `https://`, or `www.`.  `"https://portal.alueducation.com"` 
 4.Phone Numbers;
  Picks up international-style numbers that start with a `+` and a country code.  `"+250 788 123 456"` 



(c) How It Protects Data (Security Notes)

1.Stops HTML/script tricks: 
Every input passes through a cleanup step (`sanitize_input()`) that removes HTML tags and script snippets before any extraction happens, so the text can't be used to inject anything harmful.

2.Doesn't trust regex alone: 
A string of digits isn't treated as a valid credit card just because it's the right length — it also has to pass the Luhn checksum (`is_valid_luhn()`) before it's accepted.
3.Masks sensitive info right away:
As soon as a card number or email is found, it gets partially hidden using `mask_email()` and `mask_credit_card()`. The full, unmasked versions are never written to the output file or printed anywhere.
4.Regex written to avoid slowdowns:
The patterns use clear character rules and word boundaries (`\b`) instead of open-ended, nested patterns — this keeps the script fast and avoids it getting stuck processing weird or malicious input (a problem known as ReDoS).



(d) How to Run It

What you need;
 Python 3.8 or newer

Steps;

1. Put your text into `input/raw-text.txt`.
2. Run the script from the project's root folder:

```bash
python src/main.py
```

3. Open `output/sample-output.json` to see the results.

---

Example Output;

```json
{
    "alu_emails": [
        "a**********e@alueducation.com",
        "d********i@alumni.alueducation.com"
    ],
    "masked_credit_cards": [
        "****-****-****-1881"
    ],
    "urls": [
        "https://portal.alueducation.com/dashboard"
    ],
    "phone_numbers": [
        "+250 788 123 456"
    ]
}
```