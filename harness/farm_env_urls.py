import sys,json,re,time,datetime,requests
from concurrent.futures import ThreadPoolExecutor
E="https://router.huggingface.co/featherless-ai/v1/completions"; M="Qwen/Qwen3.8-Flash-Next"
tk=[l.strip().split("=",1)[1] for l in open(".env") if l.startswith("HF_TOKEN=")][0]
HOST="http://routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com/proxy_temp_file/"
env=sys.argv[1]; N=int(sys.argv[2]); OUT=sys.argv[3]
PREFIX=HOST+env+"/"
s=requests.Session(); s.headers["Authorization"]=f"Bearer {tk}"
def one(_):
    p={"model":M,"prompt":PREFIX,"max_tokens":160,"temperature":1.0,"top_p":1.0,"top_k":20}
    for _a in range(4):
        try:
            r=s.post(E,json=p,timeout=(15,150))
            if r.status_code in (429,402,503): time.sleep(3); continue
            c=r.json()["choices"][0]; return c.get("text") or "", c.get("finish_reason")
        except Exception: time.sleep(2)
    return "",None
TRACE=re.compile(r"trace_?([0-9a-fA-F]{21,34})")
REQ=re.compile(r"requestId_?([0-9a-fA-F]{8,40})")
EXP=re.compile(r"[Ee]xpires=(\d{10})")
KEY=re.compile(r"OSSAccessKeyId=(LTAI[0-9A-Za-z]+)")
def decode(tid):
    try:
        ip=".".join(str(int(tid[i:i+2],16)) for i in range(0,8,2))
        ts=int(tid[8:21]); dt=datetime.datetime.fromtimestamp(ts/1000,datetime.UTC)
        return ip,dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception: return None,None
recs=[]
with ThreadPoolExecutor(max_workers=6) as ex:
    for i,(txt,fin) in enumerate(ex.map(one,range(N))):
        full=PREFIX+txt
        tm=TRACE.search(full); tid=tm.group(1) if tm else None
        ip,dt=decode(tid) if tid else (None,None)
        dm=re.search(r"/(20\d\d-\d\d-\d\d)/",full)
        rec={"i":i,"env":env,"finish":fin,"full":full,
             "trace":tid,"ip":ip,"trace_dt":dt,
             "path_date":dm.group(1) if dm else None,
             "requestId":(REQ.search(full).group(1) if REQ.search(full) else None),
             "expires":(int(EXP.search(full).group(1)) if EXP.search(full) else None),
             "key":(KEY.search(full).group(1) if KEY.search(full) else None)}
        recs.append(rec)
json.dump(recs,open(OUT,"w"),indent=0)
dec=[r for r in recs if r["trace_dt"]]
print(f"env={env} n={len(recs)} with_decodable_trace={len(dec)} with_full_key={sum(1 for r in recs if r['key'])}")
