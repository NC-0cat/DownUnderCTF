
# DownUnderCTF-sodium

hello there 
I’m Fahad Almutairi AKA phisher

![](https://cdn-images-1.medium.com/max/2000/1*z5Z7tYsR5XBkoWcK_vg8Ww.png)

**Challenge Overview**
 A Flask-based “customer” app accepts a POST url parameter, blacklists only URL **schemes** (file:, gopher: etc.) via urlparse(url).scheme, and then calls urlopen(url), giving the response back. Behind the scenes, an internal RPC service (Python+h11) listens on 127.0.0.1:8081 with a /stats endpoint that verifies X-Forwarded-For: 127.0.0.1 against a hardcoded allow list . verifies an auth-key header against its AUTHENTICATION_KEY loaded from .env.**Logs every** query parameter via logger.error(param).Renders logs and configuration (partial key preview) back to the caller.

![](https://cdn-images-1.medium.com/max/2062/1*k9BWCtl6_7LY-70NCv_FmQ.png)

**Whitespace SSRF Bypass**: Prefix file:// with a leading space so urlparse(" file:///…").scheme == "" but urlopen(" file:///…") still reads the file. 
CVE-2023–24329 , such a sample bug in python < 3.11 is wild , 
any way back to the chall we use this ssrf to read local file 
but we can’t directly read the env in the rpc “/home/rpcservice/rpc_service/.env” where the flag is stored from the customer app however we can read from ‘/home/customerapp/customer_app/.env’

![](https://cdn-images-1.medium.com/max/2000/1*B0-fWwJCXbMvLBCdVec5lw.png)

now we have what we need to pivot to the rpc app and find a way to read the flag

RPC app : 
the app verivy incoming request by an allow list which is hard coded to be 127.0.0.1

![](https://cdn-images-1.medium.com/max/2000/1*FUJtTmwqRbjUSE-ngfSPMA.png)

but we can easily bypass that by adding double ‘x-forwarded-for: dummy’
‘x-forwarded-for: 127.0.0.1’
now we can poisone the log 
**format-string injection** bug in the RPC’s build_stats_page()

![](https://cdn-images-1.medium.com/max/2000/1*dxMT0P8OZOOK7PNzHQ3VcQ.png)

“param={config.__init__.__globals__[os].environ}”
into debug.log (because the code blindly logger.error(param) for every query-param).
**First .format(logs=…)** only replaces {logs} — it leaves any other {…} untouched.**Second .format(config=config)** walks the entire template and treats *every* {…} as a field to evaluate against the config object.{config} → your usual repr(config).**But** {config.__init__.__globals__[os].environ} → Python actually looks up config.__init__.__globals__[os].environ and injects the full os.environ dict right into the HTML response.That two-step formatting on untrusted, un-escaped input is the root bug

![](https://cdn-images-1.medium.com/max/2346/1*5A0p7tCS0BNAWlhfvrwVYg.png)

and we got our flag , thanks for reading

If you want to join us : [https://n4c4t.github.io/N4C-T/](https://n4c4t.github.io/N4C-T/)
