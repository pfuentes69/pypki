Here’s a full set of functions for both the `CertificationAuthorities` and `CertificateTemplates` tables, assuming you're using `mysql.connector` as your MySQL database connector in Python.

I'll follow your requested structure:

---

### ✅ Common Setup

```python
import mysql.connector
import json

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='your_user',
        password='your_password',
        database='your_database'
    )
```

---

## 🔹 CertificationAuthorities

### 1. List of (id, ca_name) tuples

```python
def get_certification_authorities_list():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, ca_name FROM CertificationAuthorities")
    result = cursor.fetchall()
    cursor.close()
    conn.close()
    return result
```

### 2. JSON representation of the list

```python
def get_certification_authorities_json():
    ca_list = get_certification_authorities_list()
    return json.dumps([{"id": ca[0], "name": ca[1]} for ca in ca_list], indent=2)
```

### 3. Get full record by ID as dict

```python
def get_certification_authority_by_id(ca_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM CertificationAuthorities WHERE id = %s", (ca_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result
```

### 4. JSON representation of record

```python
def get_certification_authority_json_by_id(ca_id):
    record = get_certification_authority_by_id(ca_id)
    return json.dumps(record, indent=2)
```

---

## 🔹 CertificateTemplates

### 1. List of (id, name) tuples

```python
def get_certificate_templates_list():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM CertificateTemplates")
    result = cursor.fetchall()
    cursor.close()
    conn.close()
    return result
```

### 2. JSON representation of the list

```python
def get_certificate_templates_json():
    tmpl_list = get_certificate_templates_list()
    return json.dumps([{"id": t[0], "name": t[1]} for t in tmpl_list], indent=2)
```

### 3. Get full record by ID as dict

```python
def get_certificate_template_by_id(template_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM CertificateTemplates WHERE id = %s", (template_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result
```

### 4. JSON representation of record

```python
def get_certificate_template_json_by_id(template_id):
    record = get_certificate_template_by_id(template_id)
    return json.dumps(record, indent=2)
```

---

Let me know if you’d like these in a module format or want unit tests for them too.