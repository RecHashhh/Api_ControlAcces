from logging.config import dictConfig
import logging
from uuid import uuid4
from flask import Flask, jsonify, request, g
from flask_sqlalchemy import SQLAlchemy
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
from uuid import uuid4
from flask_principal import Principal, Permission, RoleNeed, identity_loaded, UserNeed, Identity, identity_changed
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required
from flask_limiter import Limiter
from flask import redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash
import json
from sqlalchemy.orm import scoped_session, sessionmaker
from marshmallow import Schema, fields, validate, ValidationError

# Configuración de logging

dictConfig({
    "version": 1,
    "formatters": {
        "default": {
            "format": "[%(asctime)s] %(levelname)s %(filename)s:%(lineno)d - %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "audit": {
            "format": "[%(asctime)s] [AUDIT] %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "default",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "flask.log",
            "formatter": "default",
        },
        "audit_file": {
            "class": "logging.FileHandler",
            "filename": "audit.log",
            "formatter": "audit",
        },
    },
    "root": {
        "level": "DEBUG",
        "handlers": ["console", "file"]
    },
    "loggers": {
        "audit": {
            "level": "INFO",
            "handlers": ["audit_file"],
            "propagate": False
        }
    }
})



app = Flask(__name__)

port_number = 7002  # puerto de trabajo


#Configure
app.config['SECRET_KEY']= 'super_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Willrbac_principal.db'

#initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
principal = Principal(app)  

# Rate limiter
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["30 per minute"])

# Logger de auditoría
logging.basicConfig(level=logging.INFO)
audit_logger = logging.getLogger('audit')

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(80), nullable=False)
    direccion = db.Column(db.String(120), nullable=False)
    telefono = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    contrasena = db.Column(db.String(80), nullable=False)
    roles = db.Column(db.String(80))


class Bitacora(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    idUsuario = db.Column(db.Integer, nullable=False)
    tipoUsuario = db.Column(db.String(50), nullable=False)
    fecha = db.Column(db.String(20), nullable=False)
    accion = db.Column(db.String(200), nullable=False)


class ConfiguracionAcceso(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    idUsuario = db.Column(db.Integer, nullable=False)
    tipoUsuario = db.Column(db.String(50), nullable=False)
    permisos = db.Column(db.String(200))


class SolicitudAsistencia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    idResidente = db.Column(db.Integer, nullable=False)
    descripcion = db.Column(db.String(200))
    fecha = db.Column(db.String(20))
    estado = db.Column(db.String(20))


# Crear la base de datos y las tablas al iniciar la aplicación
with app.app_context():
    db.create_all()
    
#Set up user loader
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get((user_id))

#Create Roles
admin_permission = Permission(RoleNeed('Administrador'))
residente_permission = Permission(RoleNeed('Residente'))
guardia_permission = Permission(RoleNeed('GuardiaSeg'))  
visita_permission = Permission(RoleNeed('Visita'))


# Create user roles dynamically when identity changes
@identity_loaded.connect_via(app)
def on_identity_loader(sender, identity):
    identity.user = current_user
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))
    
    # Add user roles to identity
    if hasattr(current_user, 'roles'):
        for role in current_user.roles.split(','):
            identity.provides.add(RoleNeed(role))



# Ensure database is connected
@app.before_request
def connect_db():
    db.create_all()



@app.route('/login/<username>', methods=['POST'])
def login(email):
    data = request.get_json()
    user = Usuario.query.filter_by(email=email).first()  # Suponiendo que usas el email para iniciar sesión
    
    if user and check_password_hash(user.contrasena, data['contrasena']):
        login_user(user)
        identity_changed.send(app, identity=Identity(user.id))
        return redirect(url_for('index'))
    
    return f'User {email} not found or password is incorrect', 404


@app.route('/index')
@limiter.limit('5 per minute', override_defaults=True)
def index():
    return jsonify({"Welcome to the Residential Access Control System!"})


#METODOS DE ACCESO A LA API
#---BITACORA ----------

# curl -v http://localhost:7002/bitacora
@app.route('/bitacora', methods=['GET'])
@login_required
@admin_permission.require(http_exception=403)
@guardia_permission.require(http_exception=403)
@limiter.limit('2 per minute', override_defaults=True)
def get_bitacora():
    bitacoras = Bitacora.query.all()
    return jsonify([{
        'id': b.id,
        'idUsuario': b.idUsuario,
        'tipoUsuario': b.tipoUsuario,
        'fecha': b.fecha,
        'accion': b.accion
    } for b in bitacoras])

@app.route('/bitacora', methods=['POST'])
@login_required
@admin_permission.require(http_exception=403)
@guardia_permission.require(http_exception=403)
@limiter.limit('2 per minute', override_defaults=True)
def create_bitacora():
    data = request.get_json()
    new_bitacora = Bitacora(
        idUsuario=data['idUsuario'],
        tipoUsuario=data['tipoUsuario'],
        fecha=data['fecha'],
        accion=data['accion']
    )
    db.session.add(new_bitacora)
    db.session.commit()
    
    audit_logger.info(f'New bitacora entry created: {new_bitacora}')
    
    return jsonify({'message': 'Bitacora entry created successfully!'}), 201

@app.route('/bitacora/<int:id>', methods=['PUT'])
@login_required
@admin_permission.require(http_exception=403)
@guardia_permission.require(http_exception=403)
@limiter.limit('2 per minute', override_defaults=True)
def update_bitacora(id):
    data = request.get_json()
    bitacora = Bitacora.query.get_or_404(id)

    bitacora.idUsuario = data.get('idUsuario', bitacora.idUsuario)
    bitacora.tipoUsuario = data.get('tipoUsuario', bitacora.tipoUsuario)
    bitacora.fecha = data.get('fecha', bitacora.fecha)
    bitacora.accion = data.get('accion', bitacora.accion)

    db.session.commit()

    audit_logger.info(f'Bitacora entry updated: {bitacora}')
    
    return jsonify({'message': 'Bitacora entry updated successfully!'})

@app.route('/bitacora/<int:id>', methods=['DELETE'])
@login_required
@admin_permission.require(http_exception=403)
@guardia_permission.require(http_exception=403)
@limiter.limit('2 per minute', override_defaults=True)
def delete_bitacora(id):
    bitacora = Bitacora.query.get_or_404(id)
    
    db.session.delete(bitacora)
    db.session.commit()

    audit_logger.info(f'Bitacora entry deleted: {bitacora}')
    
    return jsonify({'message': 'Bitacora entry deleted successfully!'})

#--------USUARIOS--------
@app.route('/usuarios', methods=['GET'])
@login_required
@admin_permission.require(http_exception=403)
def get_usuarios():
    usuarios = Usuario.query.all()
    return jsonify([{
        'id': u.id,
        'nombre': u.nombre,
        'direccion': u.direccion,
        'telefono': u.telefono,
        'email': u.email,
        'roles': u.roles
    } for u in usuarios])
    
    
@app.route('/usuarios', methods=['POST'])
@login_required
@admin_permission.require(http_exception=403)
def create_usuario():
    data = request.get_json()
    
    # Encriptar la contraseña antes de almacenarla
    hashed_password = generate_password_hash(data['contrasena'], method='pbkdf2:sha256', salt_length=16)
    
    new_usuario = Usuario(
        nombre=data['nombre'],
        direccion=data['direccion'],
        telefono=data['telefono'],
        email=data['email'],
        contrasena=hashed_password,  # Almacenar la contraseña encriptada
        roles=data.get('roles', '')
    )
    
    db.session.add(new_usuario)
    db.session.commit()
    
    audit_logger.info(f'New user created: {new_usuario.email}')  # Registrar el evento de creación
    
    return jsonify({'message': 'User created successfully!'}), 201


@app.route('/usuarios/<int:id>', methods=['PUT'])
@login_required
@admin_permission.require(http_exception=403)
def update_usuario(id):
    data = request.get_json()
    usuario = Usuario.query.get_or_404(id)

    usuario.nombre = data.get('nombre', usuario.nombre)
    usuario.direccion = data.get('direccion', usuario.direccion)
    usuario.telefono = data.get('telefono', usuario.telefono)
    usuario.email = data.get('email', usuario.email)
    usuario.contrasena = data.get('contrasena', usuario.contrasena)
    usuario.roles = data.get('roles', usuario.roles)

    db.session.commit()

    audit_logger.info(f'User updated: {usuario}')
    
    return jsonify({'message': 'User updated successfully!'})

@app.route('/usuarios/<int:id>', methods=['DELETE'])
@login_required
@admin_permission.require(http_exception=403)
def delete_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    
    db.session.delete(usuario)
    db.session.commit()

    audit_logger.info(f'User deleted: {usuario.email}')  # Registrar el evento de eliminación
        
    return jsonify({'message': 'User deleted successfully!'})

#------SOLICITUD ASISTENCIA--------

@app.route('/solicitudes_asistencia', methods=['GET'])
@login_required
@guardia_permission.require(http_exception=403)
@residente_permission.require(http_exception=403)
@admin_permission.require(http_exception=403)
def get_solicitudes_asistencia():
    solicitudes = SolicitudAsistencia.query.all()
    return jsonify([{
        'id': s.id,
        'idResidente': s.idResidente,
        'descripcion': s.descripcion,
        'fecha': s.fecha,
        'estado': s.estado
    } for s in solicitudes])
    
@app.route('/solicitudes_asistencia', methods=['POST'])
@login_required
@guardia_permission.require(http_exception=403)
@residente_permission.require(http_exception=403)
@admin_permission.require(http_exception=403)
def create_solicitud_asistencia():
    data = request.get_json()
    new_solicitud = SolicitudAsistencia(
        idResidente=data['idResidente'],
        descripcion=data['descripcion'],
        fecha=data['fecha'],
        estado=data['estado']
    )
    
    db.session.add(new_solicitud)
    db.session.commit()
    
    audit_logger.info(f'New assistance request created: {new_solicitud}')
    
    return jsonify({'message': 'Assistance request created successfully!'}), 201

@app.route('/solicitudes_asistencia/<int:id>', methods=['PUT'])
@login_required
@guardia_permission.require(http_exception=403)
@residente_permission.require(http_exception=403)
@admin_permission.require(http_exception=403)
def update_solicitud_asistencia(id):
    data = request.get_json()
    solicitud = SolicitudAsistencia.query.get_or_404(id)

    solicitud.idResidente = data.get('idResidente', solicitud.idResidente)
    solicitud.descripcion = data.get('descripcion', solicitud.descripcion)
    solicitud.fecha = data.get('fecha', solicitud.fecha)
    solicitud.estado = data.get('estado', solicitud.estado)

    db.session.commit()

    audit_logger.info(f'Assistance request updated: {solicitud}')
    
    return jsonify({'message': 'Assistance request updated successfully!'})

@app.route('/solicitudes_asistencia/<int:id>', methods=['DELETE'])
@login_required
@guardia_permission.require(http_exception=403)
@residente_permission.require(http_exception=403)
@admin_permission.require(http_exception=403)
def delete_solicitud_asistencia(id):
    solicitud = SolicitudAsistencia.query.get_or_404(id)

    db.session.delete(solicitud)
    db.session.commit()

    audit_logger.info(f'Assistance request deleted: {solicitud}')
    
    return jsonify({'message': 'Assistance request deleted successfully!'})

#----CONFIGURACION ACCESO--------

@app.route('/configuracion_acceso', methods=['GET'])
@login_required
@guardia_permission.require(http_exception=403)
@admin_permission.require(http_exception=403)
def get_configuracion_acceso():
    configuraciones = ConfiguracionAcceso.query.all()
    return jsonify([{
        'id': c.id,
        'idUsuario': c.idUsuario,
        'tipoUsuario': c.tipoUsuario,
        'permisos': c.permisos
    } for c in configuraciones])
    
@app.route('/configuracion_acceso', methods=['POST'])
@login_required
@guardia_permission.require(http_exception=403)
@admin_permission.require(http_exception=403)
def create_configuracion_acceso():
    data = request.get_json()
    new_configuracion = ConfiguracionAcceso(
        idUsuario=data['idUsuario'],
        tipoUsuario=data['tipoUsuario'],
        permisos=data['permisos']
    )
    db.session.add(new_configuracion)
    db.session.commit()
    
    audit_logger.info(f'New access configuration created: {new_configuracion}')
    
    return jsonify({'message': 'Access configuration created successfully!'}), 201
    
@app.route('/configuracion_acceso/<int:id>', methods=['PUT'])
@login_required
@guardia_permission.require(http_exception=403)
@admin_permission.require(http_exception=403)
def update_configuracion_acceso(id):
    data = request.get_json()
    configuracion = ConfiguracionAcceso.query.get_or_404(id)

    configuracion.idUsuario = data.get('idUsuario', configuracion.idUsuario)
    configuracion.tipoUsuario = data.get('tipoUsuario', configuracion.tipoUsuario)
    configuracion.permisos = data.get('permisos', configuracion.permisos)

    db.session.commit()

    audit_logger.info(f'Access configuration updated: {configuracion}')
    
    return jsonify({'message': 'Access configuration updated successfully!'})

@app.route('/configuracion_acceso/<int:id>', methods=['DELETE'])
@login_required
@guardia_permission.require(http_exception=403)
@admin_permission.require(http_exception=403)
def delete_configuracion_acceso(id):
    configuracion = ConfiguracionAcceso.query.get_or_404(id)
    
    db.session.delete(configuracion)
    db.session.commit()

    audit_logger.info(f'Access configuration deleted: {configuracion}')
    
    return jsonify({'message': 'Access configuration deleted successfully!'})

#---------------------------------------------------------------------    

#----- ERRORHANDLER --------------------
@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        response = e.get_response()
        response.data = jsonify({
            "code": e.code,
            "name": e.name,
            "description": e.description,
        }).data
        response.content_type = "application/json"
        
        audit_logger.error(f'HTTP Exception: {e.name} - {e.description}')  # Registrar error HTTP
        
        return response
    
    audit_logger.error(f'Internal Server Error: {str(e)}')  # Registrar error interno
    return jsonify({
        "code": 500,
        "name": "Internal Server Error",
        "description": "An unexpected error occurred."
    }), 500
    
#-------------------------------------------------------------
#-------CARGAR USUARIOS--------------------

@app.route('/usuarios/cargar', methods=['POST'])
@login_required
@admin_permission.require(http_exception=403)
def cargar_usuarios():
    # Leer el archivo JSON
    with open('usuarios.json') as f:
        usuarios = json.load(f)

    # Iterar sobre cada usuario en el archivo JSON
    for data in usuarios:
        # Encriptar la contraseña antes de almacenarla
        hashed_password = generate_password_hash(data['contrasena'], method='pbkdf2:sha256', salt_length=16)
        
        nuevo_usuario = Usuario(
            nombre=data['nombre'],
            direccion=data['direccion'],
            telefono=data['telefono'],
            email=data['email'],
            contrasena=hashed_password,  # Almacenar la contraseña encriptada
            roles=data.get('roles', '')
        )
        
        db.session.add(nuevo_usuario)

    db.session.commit()
    
    return jsonify({'message': 'Usuarios cargados exitosamente!'}), 201

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=port_number)