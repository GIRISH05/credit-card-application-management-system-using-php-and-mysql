# [Stored Cross-Site Scripting (XSS)] in [Credit Card Application Management System] <= v1.0

**BUG Author:** Girish B O

---

## Product Information

- **Vendor:** PHPGurukul  
- **Project Page:** [https://phpgurukul.com/credit-card-application-management-system-using-php-and-mysql/](https://phpgurukul.com/credit-card-application-management-system-using-php-and-mysql/)
- **Affected Version:** ≤ v1.0  
- **Tested On:** Tested on: Windows 10 / Kali Linux 2024.4 (Rolling)


---

## Vulnerability Details

- **Type:** Stored Cross-Site Scripting (XSS)
- **CWE ID:** [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- **Severity:** HIGH (CVSS 3.1 Score: 8.0)
- **Attack Vector:** Remote, Persistent

---

## Root Cause

User-controlled input such as the **Full Name** and **Father’s Name** fields are not properly sanitized or encoded before being rendered in the **Admin Panel (new-ccapplication.php)**. This allows a stored JavaScript payload to be injected and executed when viewed by an admin.

---

## Proof of Concept (PoC)

### Step 1: Navigate to the application form

URL: `http://target/ccams/index.php`

Enter the following payload in the **Full Name** or **Father’s Name** field:

![image](https://github.com/user-attachments/assets/ff1535ab-7883-46de-8912-8fabbf418045)

Submit the application form.

### Step 2: Admin views new applications

URL: `http://target/ccams/admin/new-ccapplication.php`

Once the admin navigates to the application view, the stored script will execute and display an alert box.
![image](https://github.com/user-attachments/assets/b9618a08-26de-4e93-afa0-1643e82c8403)

---

## Impact

This vulnerability allows an attacker to inject and execute malicious JavaScript in the context of the admin user’s browser, leading to:

- Session hijacking
- Credential theft
- Admin panel manipulation
- Arbitrary redirection
- Data tampering

---

## Recommendations

- Sanitize all user inputs using `htmlspecialchars()` or equivalent.
- Encode dynamic content before rendering it in HTML.
- Apply server-side input validation.
- Implement Content Security Policy (CSP) headers.
- Use frameworks or libraries that auto-escape output (e.g., Twig, Blade, etc.).

---

## Disclaimer

This report and proof of concept are provided for educational and ethical testing purposes only.

