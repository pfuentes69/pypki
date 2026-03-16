Here is a **Flask API endpoint** for `/api/certificate` that returns a **paged list of certificates** from your `Certificates` table, with optional filtering by `ca_id` and `template_id`.

---

### ✅ Assumptions:
- You're using `mysql.connector` or SQLAlchemy — I’ll write a version using **`mysql.connector`** (based on your preference).
- You have a database connection utility ready (e.g., `get_db_connection()`).

---

### 📁 Code for the API route (`routes/main_routes.py`):

```python
from flask import Blueprint, request, jsonify
import mysql.connector
from api.db import get_db_connection  # Adjust based on your project structure

bp = Blueprint('main_routes', __name__)

@bp.route('/certificate', methods=['GET'])
def list_certificates():
    try:
        # Get query parameters
        ca_id = request.args.get('ca_id', type=int)
        template_id = request.args.get('template_id', type=int)
        page = request.args.get('page', default=1, type=int)
        per_page = request.args.get('per_page', default=10, type=int)

        offset = (page - 1) * per_page

        # Build SQL query dynamically
        query = """
            SELECT id, ca_id, template_id, serial_number, subject_name,
                   not_before, not_after, status
            FROM Certificates
            WHERE 1=1
        """
        params = []

        if ca_id is not None:
            query += " AND ca_id = %s"
            params.append(ca_id)

        if template_id is not None:
            query += " AND template_id = %s"
            params.append(template_id)

        query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
        params.extend([per_page, offset])

        # Execute query
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        results = cursor.fetchall()

        # Get total count for pagination
        count_query = "SELECT COUNT(*) FROM Certificates WHERE 1=1"
        count_params = []

        if ca_id is not None:
            count_query += " AND ca_id = %s"
            count_params.append(ca_id)

        if template_id is not None:
            count_query += " AND template_id = %s"
            count_params.append(template_id)

        cursor.execute(count_query, count_params)
        total = cursor.fetchone()['COUNT(*)']

        cursor.close()
        conn.close()

        return jsonify({
            "page": page,
            "per_page": per_page,
            "total": total,
            "certificates": results
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

---

### 🧱 Example response:

```json
{
  "page": 1,
  "per_page": 10,
  "total": 2,
  "certificates": [
    {
      "id": 1,
      "ca_id": 2,
      "template_id": 1,
      "serial_number": "A1B2C3",
      "subject_name": "CN=Device 01",
      "not_before": "2025-05-01T10:00:00",
      "not_after": "2026-05-01T10:00:00",
      "status": "Active"
    }
  ]
}
```

---

Would you like me to provide a SQLAlchemy-based version or help add filtering by status or date range as well?