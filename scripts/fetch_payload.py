"""Fetch official pinned runtime components; never executes the VPN or installer."""
import hashlib,json,pathlib,urllib.request,zipfile,io,shutil

ROOT=pathlib.Path(__file__).resolve().parents[1]
OUT=ROOT/'vendor-assets';OUT.mkdir(exist_ok=True)
LICENSES=OUT/'licenses';LICENSES.mkdir(exist_ok=True)
def get(url):
    req=urllib.request.Request(url,headers={'User-Agent':'AlanPN-local-build/0.1'})
    with urllib.request.urlopen(req,timeout=60) as r:return r.read()
def digest(data):return hashlib.sha256(data).hexdigest()

release=json.loads(get('https://api.github.com/repos/XTLS/Xray-core/releases/tags/v26.10.31'))
asset=next(a for a in release['assets'] if a['name']=='Xray-windows-64.zip')
expected=asset.get('digest','')
if not expected.startswith('sha256:'):raise RuntimeError('Official GitHub asset digest missing; do not bypass verification')
xray=get(asset['browser_download_url'])
assert digest(xray)==expected.removeprefix('sha256:'),'Xray checksum mismatch'
with zipfile.ZipFile(io.BytesIO(xray)) as z:
    (OUT/'xray.exe').write_bytes(z.read('xray.exe'))
    for name in z.namelist():
        if 'license' in name.lower() and not name.endswith('/'):
            (LICENSES/('xray-'+pathlib.Path(name).name)).write_bytes(z.read(name))
wintun=get('https://www.wintun.net/builds/wintun-0.14.1.zip')
assert digest(wintun)=='07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51','Wintun checksum mismatch'
with zipfile.ZipFile(io.BytesIO(wintun)) as z:
    (OUT/'wintun.dll').write_bytes(z.read('wintun/bin/amd64/wintun.dll'))
    for name in z.namelist():
        if name.lower().endswith(('license.txt','copying')):(LICENSES/('wintun-'+pathlib.Path(name).name)).write_bytes(z.read(name))
if not any(p.name.startswith('xray-') for p in LICENSES.iterdir()):
    (LICENSES/'xray-LICENSE').write_bytes(get('https://raw.githubusercontent.com/XTLS/Xray-core/v26.10.31/LICENSE'))
manifest={n:digest((OUT/n).read_bytes()) for n in ['xray.exe','wintun.dll']}
(OUT/'payload-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
provenance={'xray':{'version':'26.10.31','archiveSHA256':digest(xray),'source':asset['browser_download_url']},'wintun':{'version':'0.14.1','archiveSHA256':digest(wintun),'source':'https://www.wintun.net/builds/wintun-0.14.1.zip'}}
(OUT/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
print('Official Xray/Wintun archives verified and staged; no executable started')
