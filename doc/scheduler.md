To run periodic tasks in a Python Flask application, you have several good options depending on your requirements:

---

### ✅ **Option 1: Use `APScheduler` (Simple & Flask-friendly)**
`APScheduler` integrates well with Flask and is great for lightweight periodic jobs.

**Install it**:
```bash
pip install APScheduler
```

**Example usage**:
```python
from flask import Flask
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

app = Flask(__name__)

def my_periodic_task():
    print("Task is running!")

scheduler = BackgroundScheduler()
scheduler.add_job(func=my_periodic_task, trigger="interval", seconds=10)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

@app.route("/")
def index():
    return "Scheduler running in background"

if __name__ == "__main__":
    app.run()
```

---

### ✅ **Option 2: Use Celery (Best for distributed/long-running tasks)**
If your tasks might be heavy or need retries or queuing, Celery is a good fit.

**Install requirements**:
```bash
pip install celery redis
```

**Configure your Flask app with Celery** (example using Redis as the broker):

```python
# celery_app.py
from celery import Celery

def make_celery(app_name=__name__):
    return Celery(app_name, broker='redis://localhost:6379/0')
```

**Define tasks**:
```python
# tasks.py
from celery_app import make_celery

celery = make_celery()

@celery.task
def my_periodic_task():
    print("Running periodic task")
```

Then you can set periodic tasks using Celery Beat.

---

### ✅ **Option 3: OS Cron Jobs (Simple external scheduler)**
If you don't need your periodic task tied tightly to Flask, just write a script and schedule it using `cron` (Linux/macOS) or Task Scheduler (Windows).

---

### Which one should you use?
- **For simple in-app timers:** `APScheduler`
- **For distributed, retryable, background jobs:** `Celery`
- **For simple external scripts:** Cron jobs

---

Let me know your exact use case (e.g., task duration, need for retries, persistence), and I can suggest the best one.