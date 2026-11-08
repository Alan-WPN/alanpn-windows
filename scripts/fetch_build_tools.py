"""Fetch a checksum-pinned NSIS tool and collect dependency license notices."""
import hashlib,io,json,pathlib,subprocess,urllib.request,zipfile,shutil
root=pathlib.Path(__file__).resolve().parents[1]
url='https://downloads.sourceforge.net/project/nsis/NSIS%203/3.13/nsis-3.13.zip'
expected='ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8'
with urllib.request.urlopen(url,timeout=90) as response:data=response.read()
if hashlib.sha256(data).hexdigest()!=expected:raise RuntimeError('NSIS checksum mismatch')
target=root/'build/tools';target.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(io.BytesIO(data)) as archive:
 for item in archive.infolist():
  destination=(target/item.filename).resolve()
  if not destination.is_relative_to(target.resolve()):raise RuntimeError('Unsafe archive path')
 archive.extractall(target)
subprocess.run(['go','mod','download'],cwd=root,check=True)
text=subprocess.check_output(['go','list','-m','-json','all'],cwd=root,text=True)
decoder=json.JSONDecoder();licenses=root/'vendor-assets/licenses';licenses.mkdir(parents=True,exist_ok=True)
while text.strip():
 text=text.lstrip();module,end=decoder.raw_decode(text);text=text[end:]
 directory=module.get('Dir')
 if not directory or module.get('Main'):continue
 for file in pathlib.Path(directory).iterdir():
  if file.is_file() and file.name.lower().startswith(('license','copying','notice','copyright')):
   shutil.copyfile(file,licenses/(module['Path'].replace('/','-')+'-'+file.name))
print('Build tool verified and dependency licenses collected; no installer executed')
