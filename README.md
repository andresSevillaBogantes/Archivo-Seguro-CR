# Archivo Seguro CR

Programa educativo para compartir archivos PDF, TXT y PNG de hasta 5 MiB.

## Cómo abrirlo en Windows

1. Instale Python 3.11 o posterior desde https://www.python.org/downloads/ y marque «Add Python to PATH».
2. Extraiga el ZIP y haga doble clic en `iniciar.bat` (necesita internet la primera vez).
3. Pulse «Abrir o crear un perfil» y elija una carpeta distinta para Alicia, Bruno y Carla.
4. Para abrir dos ventanas, ejecute `iniciar.bat` dos veces.
5. En cada perfil, exporte su clave pública y compártala con los otros perfiles.
6. Agregue los contactos y compare la huella SHA-256 **directamente** con el perfil de origen antes de confirmar.
7. Alicia selecciona el archivo y a Bruno; guarda el paquete JSON.
8. Bruno importa el paquete, escribe su contraseña y elige dónde guardar el archivo.
9. Carla no debe poder abrir el paquete dirigido a Bruno. Tampoco se aceptan paquetes modificados ni repetidos.

**Importante:** las claves privadas permanecen en las carpetas de los perfiles y están cifradas con contraseña. Nunca las publique en GitHub. Use documentos y nombres ficticios.

## Explicación sencilla

AES-GCM protege el documento con una clave nueva de 32 bytes. RSA-OAEP protege esa clave para Bruno. RSA-PSS firma todos los datos del paquete. La huella SHA-256 permite confirmar los contactos. Se usan claves RSA separadas de 2048 bits para cifrar y firmar. `os.urandom` y `secrets` generan valores aleatorios seguros del sistema; el identificador tiene 16 bytes y el nonce de AES-GCM 12 bytes. Cada paquete contiene versión, ruta, identificador, emisor, destinatario, nombre, clave protegida, nonce y contenido cifrado; todo ello queda firmado. La clave de contenido y las claves privadas no se incluyen en el paquete en texto claro.

La interfaz usa seis operaciones de la clase `Seguro`: `crear_identidad(nombre, contraseña)`, `exportar_publicas(ruta)`, `registrar_contacto(ruta, confirmado)`, `crear_envio(archivo, destinatario, contraseña, salida)`, `recibir_envio(paquete, contraseña, salida)` e `historial()`. Ante datos inválidos se muestra un error y no se entrega contenido.

## Comparación de bibliotecas

PyCA cryptography permite AES-GCM, RSA-OAEP y RSA-PSS, por eso se eligió. Libsodium ofrece secretbox, sealed boxes y Ed25519, pero habría que organizar otra combinación de operaciones. Se utiliza `cryptography>=42,<47`; la versión exacta instalada se puede ver con `py -m pip show cryptography`.

## Límites

Es una demostración educativa, no una aplicación auditada para uso empresarial. La contraseña protege las claves guardadas, pero durante el uso las claves pueden estar en memoria. Si se pierde la carpeta de perfiles o la contraseña, no se puede recuperar el contenido. El programa exige que el receptor elija la ruta de salida y no sobreescribe archivos existentes. No guarda documentos descifrados en el historial.

## Pruebas

Ejecute `py pruebas.py` para realizar las ocho pruebas y el experimento de 20 envíos. Se crean perfiles temporales y no se publican claves privadas. Guarde la salida de pantalla como evidencia para el trabajo. La prueba P5 exige confirmación de la huella, mientras P8 prueba directamente AES-GCM sin depender de la firma.

## Video

Muestre dos ventanas, los perfiles, la confirmación de huellas, un envío de Alicia a Bruno, el rechazo en Carla, la ejecución de `pruebas.py` y el historial. El video debe durar entre 4 y 10 minutos.
