import json, tempfile, base64
from pathlib import Path
from seguridad import Seguro, canonical, b64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

def run():
    results=[]
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        users={name:Seguro(root/name) for name in ('Alicia','Bruno','Carla')}
        for name,u in users.items():u.crear_identidad(name,'ClavePrueba123')
        for name,u in users.items():
            u.exportar_publicas(root/(name+'.json'))
        for name,u in users.items():
            for other in users:
                if name!=other:u.registrar_contacto(root/(other+'.json'),True)
        original=root/'ejemplo.txt';original.write_bytes(b'Archivo de prueba para Bruno.\n')
        package=root/'envio.json'
        users['Alicia'].crear_envio(original,'Bruno','ClavePrueba123',package)
        def expect(label,func):
            try:func();results.append((label,'OK'))
            except Exception as e:results.append((label,'FALLO: '+str(e)))
        def p1():
            out=root/'recuperado.txt';users['Bruno'].recibir_envio(package,'ClavePrueba123',out)
            assert out.read_bytes()==original.read_bytes()
        expect('P1 Entrega correcta',p1)
        def rejected(user,path,output):
            try:user.recibir_envio(path,'ClavePrueba123',output)
            except (ValueError,KeyError):
                assert not output.exists();return
            raise AssertionError('El paquete fue aceptado sin permiso')
        expect('P2 Carla no puede abrir',lambda:rejected(users['Carla'],package,root/'carla.txt'))
        outer=json.loads(package.read_text())
        def modified(field,value,file):
            payload=json.loads(base64.b64decode(outer['datos']))
            payload[field]=value(payload[field])
            file.write_text(json.dumps({'datos':b64(canonical(payload)),'firma':outer['firma']}))
        changed=root/'alterado.json'
        def flip(s):
            data=bytearray(base64.b64decode(s));data[0]^=1;return b64(data)
        modified('contenido',flip,changed)
        expect('P3 Contenido alterado',lambda:rejected(users['Bruno'],changed,root/'alterado.txt'))
        changed2=root/'cabecera.json';modified('destinatario',lambda s:'0'*64,changed2)
        expect('P4 Cabecera alterada',lambda:rejected(users['Bruno'],changed2,root/'cabecera.txt'))
        def p5():
            old=users['Bruno'].contactos()['Alicia']['id']
            fake=dict(users['Carla']._public());fake['nombre']='Alicia'
            from seguridad import fingerprint
            fake['id']=fingerprint({k:fake[k] for k in ('nombre','cifrado','firma')})
            path=root/'sustituta.json';path.write_text(json.dumps(fake))
            try:users['Bruno'].registrar_contacto(path,False)
            except ValueError:pass
            assert users['Bruno'].contactos()['Alicia']['id']==old
        expect('P5 Clave sustituida',p5)
        expect('P6 Repeticion tras reiniciar',lambda:rejected(Seguro(root/'Bruno'),package,root/'repetido.txt'))
        def p7():
            version=root/'version.json';modified('version',lambda _:99,version)
            rejected(users['Bruno'],version,root/'version.txt')
            missing=root/'falta.json'
            obj=json.loads(base64.b64decode(outer['datos']));del obj['nonce']
            missing.write_text(json.dumps({'datos':b64(canonical(obj)),'firma':outer['firma']}))
            rejected(users['Bruno'],missing,root/'falta.txt')
            big=root/'grande.txt';big.write_bytes(b'x'*(5*1024*1024+1))
            try:users['Alicia'].crear_envio(big,'Bruno','ClavePrueba123',root/'big.json')
            except ValueError:return
            raise AssertionError('Acepto archivo grande')
        expect('P7 Formato y tamano',p7)
        def p8():
            key=AESGCM.generate_key(bit_length=256);nonce=bytes(range(12))
            cipher=bytearray(AESGCM(key).encrypt(nonce,b'prueba',None));cipher[-1]^=1
            try:AESGCM(key).decrypt(nonce,bytes(cipher),None)
            except InvalidTag:return
            raise AssertionError('No detecto alteracion')
        expect('P8 Cifrado autenticado',p8)
        ids=set();nonces=set();packages=set();good=0
        for i in range(20):
            p=root/f'paquete{i}.json';ident=users['Alicia'].crear_envio(original,'Bruno','ClavePrueba123',p)
            data=json.loads(base64.b64decode(json.loads(p.read_text())['datos']))
            ids.add(ident);nonces.add(data['nonce']);packages.add(p.read_bytes())
            out=root/f'salida{i}.txt';users['Bruno'].recibir_envio(p,'ClavePrueba123',out)
            good+=int(out.read_bytes()==original.read_bytes())
        results.append(('20 envios: ids={}, nonces={}, paquetes={}, recuperados={}'.format(len(ids),len(nonces),len(packages),good),'OK' if (len(ids),len(nonces),len(packages),good)==(20,20,20,20) else 'FALLO'))
    for name,status in results:print(name+': '+status)
    print('TOTAL:',sum(s=='OK' for _,s in results),'de',len(results))
    return all(s=='OK' for _,s in results)
if __name__=='__main__':raise SystemExit(0 if run() else 1)
