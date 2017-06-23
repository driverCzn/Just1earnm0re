```bash
cd /tmp

echo "\
MIGtAgEAAiEA5tygpSZdOZUMfuO3oTGWR4cALBtWui5UzrQw2/8JlZ0CAwEAAQIh
AI9n4Yp1KFfKlHaF8d15tgUONQXn+e3aI+beFKoi2XipAhEA/ZkHPmcDwXIqloGr
minb1wIRAOkMdv7emMGd08gwwOQ6i6sCEQC0pjcXx9BQFCCsWDDCwAC/AhEAxYcn
JQeO+izH4JpSJB/rWQIRAOO9m6JHEWgzLYD+fe003vw=
-----END RSA PRIVATE KEY-----" > rsa-private
```

```python
s = '6794893f3c47247262e95fbed846e1a623fc67b1dd96e13c7f9fc3b880642e42'
print s.encode('hex')  # use later
```

```bash
echo -ne 'g\x94\x89?<G$rb\xe9_\xbe\xd8F\xe1\xa6#\xfcg\xb1\xdd\x96\xe1<\x7f\x9f\xc3\xb8\x80d.B' > secret

openssl rsautl -raw -inkey ./rsa-private -decrypt -in ./secret | xxd  # use -raw param as a workaround for padding error
```