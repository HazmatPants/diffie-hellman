I saw [this video](https://www.youtube.com/watch?v=85oMrKd8afY) on Diffie-Hellman key exchange and decided to try implement it in python.

You can use the `--verbose` option when running the script to get additional output.

When run, the script will prompt for either client or server:

```
$ python main.py
(c)lient or (s)erver?: 
```

Make sure to run the server first, then the client.

The client and server will then negotiate an encryption key, and can now communicate securely. Read the [Wikipedia page for Diffie-Hellman](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) to see how it does this.

**Note**: This implementation is most likely not secure enough for production. I created it for fun.
