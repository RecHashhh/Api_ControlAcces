# API de Control de Accesos

![Licencia](https://img.shields.io/badge/licencia-MIT-blue)  
![Python](https://img.shields.io/badge/python-3.x-brightgreen)

## Descripción

La API de Control de Accesos es un sistema diseñado para gestionar el acceso en un entorno residencial o empresarial. Permite a los administradores gestionar usuarios, realizar auditorías mediante bitácoras y manejar solicitudes de asistencia. Implementa autenticación basada en roles y limitación de peticiones.

## Tabla de Contenidos

- [Descripción](#descripción)
- [Requisitos Previos](#requisitos-previos)
- [Instalación](#instalación)
- [Uso](#uso)
- [Endpoints](#endpoints)
  - [Usuarios](#usuarios)
  - [Bitácoras](#bitácoras)
  - [Solicitudes de Asistencia](#solicitudes-de-asistencia)
- [Autenticación y Autorización](#autenticación-y-autorización)
- [Rate Limiting](#rate-limiting)
- [Manejo de Errores](#manejo-de-errores)
- [Pruebas Unitarias](#pruebas-unitarias)
- [Contribuciones](#contribuciones)
- [Licencia](#licencia)

## Requisitos Previos

Asegúrate de tener instalado:

- Python 3.x
- Flask
- Flask-Limiter
- Flask-SQLAlchemy
- Flask-Login
- Flask-Principal

Para instalar las dependencias, ejecuta el siguiente comando:

```bash
pip install -r requirements.txt
```

## Instalación

1. Clona el repositorio:

    ```bash
    git clone https://github.com/tu-usuario/api-control-accesos.git
    cd api-control-accesos
    ```

2. Instala las dependencias:

    ```bash
    pip install -r requirements.txt
    ```

3. Configura la base de datos:

    ```bash
    python setup_database.py
    ```

4. Inicia la API:

    ```bash
    python app.py
    ```

La API estará disponible en `http://localhost:5000`.

## Uso

### Crear un usuario

```bash
POST /usuarios
```

```json
{
  "nombre": "Ana Lopez",
  "email": "ana@example.com",
  "contrasena": "12345",
  "roles": "GuardiaSeg"
}
```

### Obtener todas las entradas de la bitácora

```bash
GET /bitacora
```

### Crear una solicitud de asistencia

```bash
POST /solicitudes_asistencia
```

```json
{
  "idResidente": 5,
  "descripcion": "Puerta de acceso bloqueada",
  "fecha": "2024-09-25",
  "estado": "Pendiente"
}
```

## Endpoints

### Usuarios

- **GET /usuarios**: Lista todos los usuarios.
- **POST /usuarios**: Crea un nuevo usuario.
- **PUT /usuarios/{id}**: Actualiza un usuario existente.
- **DELETE /usuarios/{id}**: Elimina un usuario.

### Bitácoras

- **GET /bitacora**: Lista todas las entradas de la bitácora.
- **POST /bitacora**: Crea una nueva entrada de bitácora.
- **PUT /bitacora/{id}**: Actualiza una entrada de bitácora.
- **DELETE /bitacora/{id}**: Elimina una entrada de bitácora.

### Solicitudes de Asistencia

- **GET /solicitudes_asistencia**: Lista todas las solicitudes de asistencia.
- **POST /solicitudes_asistencia**: Crea una nueva solicitud de asistencia.
- **PUT /solicitudes_asistencia/{id}**: Actualiza una solicitud de asistencia.
- **DELETE /solicitudes_asistencia/{id}**: Elimina una solicitud de asistencia.

## Autenticación y Autorización

La API utiliza `Flask-Login` para autenticación y `Flask-Principal` para la autorización de roles. Existen los siguientes roles:

- **Administrador**: Acceso total.
- **GuardiaSeg**: Acceso a bitácoras y solicitudes de asistencia.
- **Residente**: Puede crear solicitudes de asistencia.
- **Visita**: Acceso limitado.

## Rate Limiting

Para proteger la API de abusos, se aplica una limitación de **30 peticiones por minuto** para la mayoría de las rutas. Rutas más sensibles, como las bitácoras, tienen un límite de **2 peticiones por minuto**. Utilizamos `Flask-Limiter` para gestionar esta funcionalidad.

## Manejo de Errores

La API maneja los siguientes errores:

- **400 Bad Request**: Petición inválida.
- **401 Unauthorized**: Autenticación fallida.
- **403 Forbidden**: Permiso denegado.
- **404 Not Found**: Recurso no encontrado.
- **500 Internal Server Error**: Error interno del servidor.

### Ejemplo de respuesta de error

```json
{
  "error": "Unauthorized",
  "message": "No tienes permisos para acceder a este recurso."
}
```

## Pruebas Unitarias

Para ejecutar las pruebas unitarias, usa el siguiente comando:

```bash
python -m unittest discover
```

## Contribuciones

Si deseas contribuir a este proyecto:

1. Haz un fork del repositorio.
2. Crea una rama para tu feature o bugfix (`git checkout -b feature-nueva`).
3. Realiza tus cambios y realiza commits descriptivos (`git commit -m "Descripción del cambio"`).
4. Envía un pull request.

## Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo [LICENSE](LICENSE) para más detalles.

---

Este README está diseñado para ser claro, conciso y proveer toda la información necesaria para que otros desarrolladores puedan entender y trabajar con tu API de Control de Accesos.
