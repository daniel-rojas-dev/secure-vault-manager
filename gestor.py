import tkinter as tk
from tkinter import messagebox, scrolledtext
import json  # Estructura de datos profesional (objetos y listas)
import os
from cryptography.fernet import Fernet # Librería principal de cifrado
from cryptography.hazmat.primitives import hashes # Para el algoritmo de hashing SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # Para derivar la llave
import base64 # Para codificar la llave en un formato compatible con Fernet

# --- CONFIGURACIÓN DE SEGURIDAD ---
# El SALT es como la 'semilla'. Se queda fija para que tu clave maestra siempre genere la misma llave.
SALT = b'\xfb\x12\x8a\x03\x11\xec\x91\xfe\x02\x15' 
ARCHIVO_JSON = "mis_datos.json"

def generar_llave(master_password):
    """Función que convierte tu palabra secreta en una llave binaria de 32 bytes segura."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000, # Repite el proceso 100k veces para que sea difícil de hackear
    )
    # Retorna la llave lista para ser usada por el cifrador
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

# --- LÓGICA DE LA APLICACIÓN ---

def abrir_panel_principal(pwd_maestra):
    """Función que construye y muestra la ventana principal tras un login exitoso."""
    ventana_login.destroy() # Cierra la ventana pequeña de login para pasar a la grande
    
    app = tk.Tk()
    app.title("Gestor de Contraseñas Pro")
    app.geometry("550x600")

    def guardar():
        """Función interna para capturar, encriptar y guardar los datos en el JSON."""
        sitio = ent_sitio.get()
        user = ent_user.get()
        contra = ent_pass.get()
        
        # IF: Verifica que el usuario no deje campos en blanco antes de procesar
        if not (sitio and user and contra):
            messagebox.showwarning("Error", "Faltan datos.")
            return

        # TRY: Intenta el proceso de encriptación y escritura en disco
        try:
            # Inicializa el motor de cifrado con la llave maestra proporcionada
            f = Fernet(generar_llave(pwd_maestra))
            
            # Crea un diccionario con el sitio y los datos ya encriptados
            datos_nuevos = {
                "sitio": sitio,
                "usuario": f.encrypt(user.encode()).decode(),
                "pass": f.encrypt(contra.encode()).decode()
            }

            lista_datos = []
            # IF: Si el archivo ya existe, carga los datos actuales para no borrarlos
            if os.path.exists(ARCHIVO_JSON):
                with open(ARCHIVO_JSON, "r") as f_json:
                    lista_datos = json.load(f_json)
            
            # Agrega el nuevo registro a la lista y sobrescribe el archivo con la lista actualizada
            lista_datos.append(datos_nuevos)
            with open(ARCHIVO_JSON, "w") as f_json:
                json.dump(lista_datos, f_json, indent=4) # indent=4 lo hace legible para humanos

            messagebox.showinfo("Éxito", "Guardado en el archivo JSON.")
            # Limpia los campos de entrada de la interfaz
            ent_sitio.delete(0, tk.END); ent_user.delete(0, tk.END); ent_pass.delete(0, tk.END)
            actualizar_lista() # Llama a la función para refrescar la tabla visual
        # EXCEPT: Si algo falla (archivo bloqueado, error de llave, etc.)
        except:
            messagebox.showerror("Error", "No se pudo guardar los datos.")

    def actualizar_lista():
        """Función que lee el JSON, desencripta los datos y los dibuja en la pantalla."""
        # Borra todos los elementos visuales actuales de la lista para redibujarlos
        for widget in frame_lista.winfo_children():
            widget.destroy() 

        # IF: Si no hay archivo de datos, no hay nada que mostrar, termina la función
        if not os.path.exists(ARCHIVO_JSON):
            return

        # TRY: Intenta leer el archivo y desencriptar cada línea
        try:
            f = Fernet(generar_llave(pwd_maestra))
            with open(ARCHIVO_JSON, "r") as f_json:
                datos = json.load(f_json) # Convierte el JSON en una lista de Python
                
                for item in datos:
                    # Desencripta el usuario y la contraseña para que sean legibles en la interfaz
                    u_claro = f.decrypt(item["usuario"].encode()).decode()
                    p_claro = f.decrypt(item["pass"].encode()).decode()
                    
                    # Crea un marco visual para cada fila de la lista
                    fila = tk.Frame(frame_lista, pady=5, bd=1, relief="sunken")
                    fila.pack(fill="x", padx=10, pady=2)
                    
                    # Dibuja las etiquetas con la información recuperada
                    tk.Label(fila, text=item["sitio"].upper(), width=12, font=("Arial", 9, "bold")).pack(side="left")
                    tk.Label(fila, text=f"User: {u_claro}", width=20, anchor="w").pack(side="left")
                    tk.Label(fila, text=f"Pass: {p_claro}", width=20, anchor="w", fg="blue").pack(side="left")
        # EXCEPT: Si falla la lectura o el descifrado, simplemente no muestra esa lista
        except:
            pass

    # --- DISEÑO DEL PANEL PRINCIPAL (TKINTER) ---
    tk.Label(app, text="➕ AGREGAR NUEVA CREDENCIAL", font=("Arial", 12, "bold")).pack(pady=10)
    
    tk.Label(app, text="Aplicación / Sitio:").pack()
    ent_sitio = tk.Entry(app, width=40); ent_sitio.pack()
    
    tk.Label(app, text="Usuario:").pack()
    ent_user = tk.Entry(app, width=40); ent_user.pack()
    
    tk.Label(app, text="Contraseña:").pack()
    ent_pass = tk.Entry(app, width=40); ent_pass.pack()
    
    tk.Button(app, text="💾 GUARDAR EN JSON", bg="#27ae60", fg="white", command=guardar).pack(pady=10)
    
    tk.Label(app, text="📋 TUS CREDENCIALES GUARDADAS", font=("Arial", 10, "bold")).pack(pady=10)
    
    # Configuración de área de scroll para soportar muchas contraseñas
    canvas = tk.Canvas(app)
    scrollbar = tk.Scrollbar(app, orient="vertical", command=canvas.yview)
    frame_lista = tk.Frame(canvas)
    
    canvas.create_window((0, 0), window=frame_lista, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    # Ajusta el área de scroll automáticamente cuando se agregan nuevos datos
    frame_lista.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    
    actualizar_lista() # Carga inicial de datos
    app.mainloop()

# --- LÓGICA DE ENTRADA (LOGIN) ---

def intentar_entrar():
    """Función que valida la clave maestra antes de permitir el acceso al panel."""
    clave = entry_login.get()
    # IF: Verifica que la caja de texto no esté vacía
    if not clave:
        messagebox.showwarning("Aviso", "Escribe la clave maestra.")
        return

    # IF: Si el archivo NO existe, significa que es la primera vez que se usa la App
    if not os.path.exists(ARCHIVO_JSON):
        messagebox.showinfo("Nuevo Usuario", "Clave maestra creada.")
        abrir_panel_principal(clave)
    # ELSE: Si el archivo existe, debemos validar que la clave sea la correcta
    else:
        # TRY: Intenta abrir el archivo y desencriptar el primer dato guardado
        try:
            with open(ARCHIVO_JSON, "r") as f_json:
                datos = json.load(f_json)
                # IF: Si el archivo existe pero está vacío (por ejemplo, borraste el contenido manualmente)
                if not datos: 
                    abrir_panel_principal(clave)
                    return
                
                # Intentamos descifrar el primer usuario de la lista como prueba de fuego
                f = Fernet(generar_llave(clave))
                f.decrypt(datos[0]["usuario"].encode())
                
                # Si la desencriptación tuvo éxito, la clave es correcta y pasamos al panel
                abrir_panel_principal(clave)
        # EXCEPT: Si la clave es incorrecta, Fernet lanzará un error y caeremos aquí
        except:
            messagebox.showerror("Error", "Clave Maestra incorrecta.")

# --- VENTANA DE LOGIN (INICIAL) ---
ventana_login = tk.Tk()
ventana_login.title("Acceso Seguro")
ventana_login.geometry("300x200")

tk.Label(ventana_login, text="ESCRIBE TU CLAVE MAESTRA", font=("Arial", 10, "bold")).pack(pady=20)
entry_login = tk.Entry(ventana_login, show="*", width=20, justify="center")
entry_login.pack()

tk.Button(ventana_login, text="ENTRAR", bg="#34495e", fg="white", command=intentar_entrar).pack(pady=20)

ventana_login.mainloop()