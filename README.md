# secure-vault-manager
Gestor de credenciales con cifrado simétrico (Fernet) y derivación de claves (PBKDF2). Un proyecto enfocado en la concienciación de ciberseguridad y la protección de datos sensibles.

# 🔐 Secure Vault Manager - Ciberseguridad Aplicada

Este proyecto es una aplicación de escritorio desarrollada en **Python** que funciona como un gestor de credenciales local. El enfoque principal no es solo la gestión de datos, sino la implementación de estándares de **criptografía robusta** para concienciar sobre la importancia de la seguridad digital.

## 🛡️ ¿Por qué este proyecto es seguro?
A diferencia de un simple archivo de texto, este sistema implementa:
* **Cifrado Simétrico:** Utiliza la librería `cryptography` con el estándar **Fernet**, que garantiza que los datos no puedan ser leídos sin la clave correcta.
* **Derivación de Clave (PBKDF2):** La "Clave Maestra" no se guarda nunca. Se utiliza un algoritmo de hashing **SHA256** con 100,000 iteraciones y un **SALT** único para generar una llave binaria segura.
* **Estructura JSON Segura:** Los datos se almacenan en un archivo `.json`, pero todo el contenido sensible (usuario y contraseña) está cifrado en formato Base64.

## 🛠️ Tecnologías Utilizadas
* **Python 3.x:** Lenguaje principal.
* **Tkinter:** Para la interfaz gráfica de usuario (GUI).
* **Fernet (Criptografía):** Motor de cifrado y descifrado.
* **JSON:** Almacenamiento de datos estructurado.

## 📋 Características Principales
* ✅ **Login con Clave Maestra:** Validación por descifrado de prueba (si la clave es incorrecta, el sistema bloquea el acceso).
* ✅ **Interfaz Intuitiva:** Sistema de scroll y visualización organizada de credenciales.
* ✅ **Persistencia de Datos:** Guardado automático y actualización en tiempo real del archivo local.

## 🏗️ Flujo de Seguridad
1. El usuario ingresa una **Clave Maestra**.
2. El sistema aplica **PBKDF2HMAC** para derivar una llave de 32 bytes.
3. Se intenta descifrar el primer registro del JSON; si falla, se deniega el acceso.
4. Al guardar, los datos pasan por el motor de cifrado antes de tocar el disco duro.

## 🧠 Conciencia sobre Ciberseguridad
Este software nace de la necesidad de entender que la **seguridad por oscuridad no es seguridad**. En el entorno actual, cifrar la información local es el primer paso para proteger la identidad digital contra filtraciones y accesos no autorizados.
