import base64, hashlib, json, os, secrets, sqlite3
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature, InvalidTag

MAX_FILE = 5 * 1024 * 1024
MAX_PACKAGE = 9 * 1024 * 1024
ROUTE = 'AES-256-GCM + RSA-OAEP-SHA256 + RSA-PSS-SHA256'
def b64(data): return base64.b64encode(data).decode('ascii')
def un64(data): return base64.b64decode(data, validate=True)
def canonical(obj): return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
def public_pem(key): return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
def load_public(pem): return serialization.load_pem_public_key(pem.encode())
def fingerprint(public): return hashlib.sha256(canonical(public)).hexdigest()
def now(): return datetime.now().isoformat(timespec='seconds')

class Seguro:
    def __init__(self, folder):
        self.folder = Path(folder).resolve()
        self.folder.mkdir(parents=True, exist_ok=True)
        self.db = self.folder / 'registro.db'
        with sqlite3.connect(self.db) as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS recepciones (id TEXT PRIMARY KEY, fecha TEXT NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS eventos (fecha TEXT, resultado TEXT, detalle TEXT)')
    def _log(self, result, detail):
        with sqlite3.connect(self.db) as conn: conn.execute('INSERT INTO eventos VALUES (?,?,?)',(now(),result,detail[:180]))
    def _file(self, name): return self.folder / name
    def _public(self):
        return json.loads(self._file('publico.json').read_text(encoding='utf-8'))
    def crear_identidad(self, name, password):
        if self._file('publico.json').exists(): raise ValueError('Este perfil ya tiene una identidad.')
        if not name.strip() or len(password)<8: raise ValueError('Escriba un nombre y una contraseña de al menos 8 caracteres.')
        enc = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sign = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = {'nombre':name.strip(), 'cifrado':public_pem(enc.public_key()), 'firma':public_pem(sign.public_key())}
        public['id'] = fingerprint(public)
        for key, fn in ((enc,'privada_cifrado.pem'),(sign,'privada_firma.pem')):
            data=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password.encode()))
            self._file(fn).write_bytes(data)
        self._file('publico.json').write_text(json.dumps(public,indent=2,ensure_ascii=False),encoding='utf-8')
        self._file('contactos.json').write_text('{}',encoding='utf-8')
        return public['id']
    def exportar_publicas(self, destination):
        public=self._public()
        Path(destination).write_text(json.dumps(public,ensure_ascii=False,indent=2),encoding='utf-8')
        return public['id']
    def leer_contacto(self, path):
        obj=json.loads(Path(path).read_text(encoding='utf-8'))
        if not isinstance(obj,dict) or not all(isinstance(obj.get(x),str) for x in ('nombre','cifrado','firma','id')): raise ValueError('El contacto está incompleto.')
        check={k:obj[k] for k in ('nombre','cifrado','firma')}
        if fingerprint(check)!=obj['id']: raise ValueError('Los datos del contacto no coinciden con su huella.')
        for field in ('cifrado','firma'):
            k=load_public(obj[field])
            if not isinstance(k,rsa.RSAPublicKey) or k.key_size<2048: raise ValueError('La clave pública no es válida.')
        return obj
    def registrar_contacto(self, path, confirmed):
        obj=self.leer_contacto(path)
        if not confirmed: raise ValueError('Primero debe confirmar la huella con la otra persona.')
        contacts=self.contactos()
        existing=contacts.get(obj['nombre'])
        contacts[obj['nombre']]=obj
        self._file('contactos.json').write_text(json.dumps(contacts,ensure_ascii=False,indent=2),encoding='utf-8')
        return 'Contacto actualizado' if existing else 'Contacto guardado'
    def contactos(self): return json.loads(self._file('contactos.json').read_text(encoding='utf-8'))
    def _private(self, name, password):
        try: return serialization.load_pem_private_key(self._file(name).read_bytes(),password=password.encode())
        except (ValueError,TypeError): raise ValueError('Contraseña incorrecta o clave dañada.')
    def crear_envio(self, file, recipient_name, password, destination):
        file=Path(file)
        if file.suffix.lower() not in ('.pdf','.txt','.png'): raise ValueError('Solo se permiten archivos PDF, TXT o PNG.')
        if file.stat().st_size>MAX_FILE: raise ValueError('El archivo supera los 5 MiB permitidos.')
        recipients=self.contactos()
        if recipient_name not in recipients: raise ValueError('Seleccione un contacto confiable.')
        sender=self._public(); recipient=recipients[recipient_name]
        private=self._private('privada_firma.pem',password)
        key=AESGCM.generate_key(bit_length=256); nonce=os.urandom(12)
        cipher=AESGCM(key).encrypt(nonce,file.read_bytes(),None)
        wrapped=load_public(recipient['cifrado']).encrypt(key,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        payload={'version':1,'ruta':ROUTE,'id':secrets.token_hex(16),'emisor':sender['id'],'destinatario':recipient['id'],'nombre':file.name,'clave_protegida':b64(wrapped),'nonce':b64(nonce),'contenido':b64(cipher)}
        data=canonical(payload)
        signature=private.sign(data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        Path(destination).write_text(json.dumps({'datos':b64(data),'firma':b64(signature)},indent=2),encoding='utf-8')
        return payload['id']
    def recibir_envio(self, package_path, password, destination):
        try:
            path=Path(package_path)
            if path.stat().st_size>MAX_PACKAGE: raise ValueError('El paquete es demasiado grande.')
            outer=json.loads(path.read_text(encoding='utf-8'))
            data=un64(outer['datos']); signature=un64(outer['firma'])
            if len(data)>MAX_PACKAGE: raise ValueError('Paquete demasiado grande.')
            payload=json.loads(data)
            if canonical(payload)!=data: raise ValueError('Formato del paquete no admitido.')
            required={'version','ruta','id','emisor','destinatario','nombre','clave_protegida','nonce','contenido'}
            if set(payload)!=required or payload['version']!=1 or payload['ruta']!=ROUTE: raise ValueError('Formato o versión no admitida.')
            if not all(isinstance(payload[k],str) for k in required-{'version'}): raise ValueError('Campos incorrectos.')
            if len(payload['id'])!=32 or any(c not in '0123456789abcdef' for c in payload['id']): raise ValueError('Identificador incorrecto.')
            me=self._public()
            if payload['destinatario']!=me['id']: raise ValueError('Este paquete no es para este perfil.')
            trusted=next((c for c in self.contactos().values() if c['id']==payload['emisor']),None)
            if trusted is None: raise ValueError('No se conoce al remitente. Primero registre su clave pública.')
            try: load_public(trusted['firma']).verify(signature,data,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
            except InvalidSignature: raise ValueError('La firma no coincide: paquete modificado o remitente incorrecto.')
            with sqlite3.connect(self.db) as conn:
                if conn.execute('SELECT 1 FROM recepciones WHERE id=?',(payload['id'],)).fetchone(): raise ValueError('Este paquete ya fue recibido anteriormente.')
            key=self._private('privada_cifrado.pem',password).decrypt(un64(payload['clave_protegida']),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            content=AESGCM(key).decrypt(un64(payload['nonce']),un64(payload['contenido']),None)
            if len(content)>MAX_FILE: raise ValueError('El contenido supera el tamaño permitido.')
            if Path(destination).suffix.lower() not in ('.pdf','.txt','.png'): raise ValueError('Guarde con extensión PDF, TXT o PNG.')
            target=Path(destination)
            if target.exists(): raise ValueError('El archivo de salida ya existe. Elija otro nombre.')
            # Registrar y guardar en el mismo flujo; no aceptar repetidos.
            with sqlite3.connect(self.db) as conn:
                conn.execute('BEGIN IMMEDIATE')
                if conn.execute('SELECT 1 FROM recepciones WHERE id=?',(payload['id'],)).fetchone(): raise ValueError('Este paquete ya fue recibido.')
                with open(target,'xb') as f: f.write(content)
                conn.execute('INSERT INTO recepciones VALUES (?,?)',(payload['id'],now()))
            self._log('ACEPTADO',payload['id'])
            return payload['id']
        except Exception as e:
            self._log('RECHAZADO',type(e).__name__)
            if isinstance(e,(InvalidTag,InvalidSignature)): raise ValueError('El contenido no pasó la comprobación de seguridad.')
            if isinstance(e,(KeyError,TypeError,UnicodeError,json.JSONDecodeError,base64.binascii.Error,OverflowError)): raise ValueError('El paquete está incompleto o dañado.')
            raise
    def historial(self):
        with sqlite3.connect(self.db) as conn: return conn.execute('SELECT fecha,resultado,detalle FROM eventos ORDER BY rowid DESC LIMIT 100').fetchall()
