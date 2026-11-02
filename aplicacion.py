import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from pathlib import Path
from seguridad import Seguro

class Ventana:
    def __init__(self, root):
        self.root=root; root.title('Archivo Seguro CR'); root.geometry('660x560')
        frame=ttk.Frame(root,padding=18); frame.pack(fill='both',expand=True)
        ttk.Label(frame,text='Archivo Seguro CR',font=('Arial',19,'bold')).pack(anchor='w')
        ttk.Label(frame,text='Proteja y comparta archivos de forma sencilla').pack(anchor='w',pady=(0,14))
        ttk.Button(frame,text='1. Abrir o crear un perfil',command=self.perfil).pack(fill='x',pady=4)
        ttk.Button(frame,text='2. Compartir mi clave pública',command=self.exportar).pack(fill='x',pady=4)
        ttk.Button(frame,text='3. Agregar un contacto de confianza',command=self.contacto).pack(fill='x',pady=4)
        ttk.Button(frame,text='4. Preparar un archivo para enviar',command=self.enviar).pack(fill='x',pady=4)
        ttk.Button(frame,text='5. Recibir y abrir un archivo',command=self.recibir).pack(fill='x',pady=4)
        ttk.Button(frame,text='6. Ver historial',command=self.historial).pack(fill='x',pady=4)
        self.status=ttk.Label(frame,text='Primero abra un perfil (por ejemplo, Alicia).',wraplength=600)
        self.status.pack(anchor='w',pady=12)
        self.output=tk.Text(frame,height=10,wrap='word');self.output.pack(fill='both',expand=True)
        self.output.insert('end','Consejo: cada persona debe usar una carpeta distinta.\n')
        self.s=None
    def info(self,msg): self.output.insert('end',msg+'\n');self.output.see('end')
    def guard(self,fn):
        try:
            if not self.s: raise ValueError('Primero abra o cree un perfil.')
            fn()
        except Exception as e: messagebox.showerror('No se pudo completar',str(e))
    def perfil(self):
        folder=filedialog.askdirectory(title='Elija la carpeta del perfil (Alicia, Bruno o Carla)')
        if not folder:return
        try:
            self.s=Seguro(folder)
            if not (Path(folder)/'publico.json').exists():
                name=simpledialog.askstring('Crear perfil','¿Cómo se llama esta persona?',parent=self.root)
                if not name:return
                password=simpledialog.askstring('Contraseña','Cree una contraseña (mínimo 8 caracteres):',show='*',parent=self.root)
                if password is None:return
                self.s.crear_identidad(name,password)
                self.info('Perfil creado: '+name+'. No comparta su contraseña.')
            else:self.info('Perfil abierto correctamente.')
            self.status.config(text='Perfil actual: '+self.s._public()['nombre']+' | Carpeta: '+folder)
        except Exception as e: messagebox.showerror('Error',str(e))
    def exportar(self):
        def run():
            path=filedialog.asksaveasfilename(title='Guardar mi clave pública',defaultextension='.json',filetypes=[('JSON','*.json')])
            if path:
                h=self.s.exportar_publicas(path);self.info('Clave pública guardada. Huella SHA-256:\n'+h)
        self.guard(run)
    def contacto(self):
        def run():
            path=filedialog.askopenfilename(title='Seleccione la clave pública recibida',filetypes=[('JSON','*.json')])
            if not path:return
            c=self.s.leer_contacto(path)
            answer=messagebox.askyesno('Confirmar identidad','Contacto: '+c['nombre']+'\n\nHuella SHA-256:\n'+c['id']+'\n\n¿Comparó esta huella directamente con la otra persona y coincide?')
            if not answer:return
            self.info(self.s.registrar_contacto(path,True)+': '+c['nombre'])
        self.guard(run)
    def password(self): return simpledialog.askstring('Contraseña del perfil','Escriba la contraseña de este perfil:',show='*',parent=self.root)
    def enviar(self):
        def run():
            contacts=list(self.s.contactos())
            if not contacts:raise ValueError('Primero agregue un contacto confiable.')
            file=filedialog.askopenfilename(title='Archivo para enviar',filetypes=[('Archivos permitidos','*.pdf *.txt *.png')])
            if not file:return
            recipient=simpledialog.askstring('Destinatario','Escriba el nombre exacto del destinatario:\n'+', '.join(contacts),parent=self.root)
            if not recipient:return
            password=self.password()
            if password is None:return
            output=filedialog.asksaveasfilename(title='Guardar paquete protegido',defaultextension='.seguro.json',filetypes=[('Paquete protegido','*.json')])
            if output:self.info('Envío preparado. Código: '+self.s.crear_envio(file,recipient,password,output))
        self.guard(run)
    def recibir(self):
        def run():
            path=filedialog.askopenfilename(title='Seleccione el paquete recibido',filetypes=[('Paquete protegido','*.json')])
            if not path:return
            password=self.password()
            if password is None:return
            output=filedialog.asksaveasfilename(title='Elija dónde guardar el archivo recuperado',filetypes=[('PDF','*.pdf'),('Texto','*.txt'),('Imagen','*.png')])
            if output:self.info('Archivo recuperado correctamente. Código: '+self.s.recibir_envio(path,password,output))
        self.guard(run)
    def historial(self):
        def run():
            self.info('--- HISTORIAL ---')
            for date,result,detail in self.s.historial():self.info(date+' | '+result+' | '+detail)
        self.guard(run)

if __name__=='__main__':
    root=tk.Tk();Ventana(root);root.mainloop()
