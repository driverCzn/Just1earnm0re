```python
import hashlib

s = 'id0-rsa.pub'

s_sha256 = hashlib.sha256(s).hexdigest()

s_md5 = hashlib.md5(s).hexdigest()
```