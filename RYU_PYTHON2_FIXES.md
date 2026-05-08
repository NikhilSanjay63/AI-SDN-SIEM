# Ryu Controller Python 2 Compatibility Fixes

This document records the errors encountered during the start-up of the Ryu SDN controllers and the corresponding fixes applied to ensure compatibility with Python 2.7.

## 1. SyntaxError: invalid syntax (f-strings)

**Location:** `sdn-service/controllers/primary_controller.py`

**Error Log:**
```python
  File "/app/controllers/primary_controller.py", line 100
    if self.redis.exists(f"blacklist:{src_ip}"):
                                             ^
SyntaxError: invalid syntax
```

**Cause:** 
The code used an f-string (`f"..."`), a feature introduced in Python 3.6. Since the Ryu manager runs on Python 2.7, the interpreter could not parse this syntax.

**Fix:**
Replaced the f-string with the Python 2 compatible `.format()` string interpolation method.

*Before:*
```python
if self.redis.exists(f"blacklist:{src_ip}"):
```

*After:*
```python
if self.redis.exists("blacklist:{}".format(src_ip)):
```

---

## 2. TypeError: unexpected keyword argument 'daemon'

**Location:** `sdn-service/controllers/security_controller.py`

**Error Log:**
```python
  File "/app/controllers/security_controller.py", line 87, in __init__
    target=self._batch_flush_loop, daemon=True
TypeError: __init__() got an unexpected keyword argument 'daemon'
```

**Cause:**
The code attempted to pass `daemon=True` as a keyword argument directly into the `threading.Thread` constructor. This keyword argument is only supported in Python 3.3 and later.

**Fix:**
Removed the `daemon=True` keyword argument from the constructor and instead set the `.daemon` property directly on the thread object before starting it, which is the standard approach in Python 2.7.

*Before:*
```python
self._flush_thread = threading.Thread(
    target=self._batch_flush_loop, daemon=True
)
self._flush_thread.start()
```

*After:*
```python
self._flush_thread = threading.Thread(
    target=self._batch_flush_loop
)
self._flush_thread.daemon = True
self._flush_thread.start()
```
