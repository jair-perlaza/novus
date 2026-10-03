from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
import os
import psutil
import scapy.all as scapy
from datetime import datetime
import threading
import time

import data_service as ds

app = Flask(__name__)
app.secret_key = os.environ.get('NOVUS_SECRET_KEY', 'clave_secreta_definitiva_para_novus_2026')

# =========================
# FLASK LOGIN CONFIG
# =========================
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Debes iniciar sesión para acceder"
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"

# =========================
# CLASE USER DEFINITIVA - PASSWORD OPCIONAL
# =========================
class User(UserMixin):
    def __init__(self, id, email, role='user', sector=None):
        self.id = id
        self.email = email
        self.role = role
        self.sector = sector or 'Sin datos disponibles'

    def __repr__(self):
        return f'<User {self.email}>'

@login_manager.user_loader
def load_user(user_id):
    if user_id is None or not str(user_id).isdigit():
        return None
    user_data = ds.load_user_by_id(int(user_id))
    if not user_data:
        return None
    return User(
        id=user_data['id'],
        email=user_data['email'],
        role=user_data['role'],
        sector=user_data['sector'],
    )

# =========================
# PROTECCIÓN GLOBAL - SIMPLIFICADA Y FUNCIONAL
# =========================
@app.before_request
def require_login():
    # Permitir rutas públicas y archivos estáticos
    if request.endpoint is None:
        return None
    
    public_routes = ['login', 'static', 'logout_seguro', 'registro_empresa', 'api_network_nodes', 'dashboard', 'xdr', 'vulnerabilidades', 'endpoints', 'automatizacion', 'reportes']
    
    if request.endpoint in public_routes or request.endpoint.startswith('static'):
        return None

    # Si no está autenticado, redirigir a login
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    return None


network_cache = []      
amenazas_detectadas = [] 

network_cache = {
    "nodes": [],
    "last_scan": None,
    "active_threats": 0
}



def get_real_system_status():
    """Extrae métricas reales del hardware"""
    return {
        "cpu": psutil.cpu_percent(interval=1),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent,
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    }

def scan_network_real():
    """
    Escaneo ARP real usando Scapy.
    Detecta automáticamente el rango de red y escanea dispositivos.
    """
    try:
        # Detectar gateway y rango de red automáticamente
        import socket
        import subprocess
        import platform
        
        print(f"[!] Detectando rango de red automáticamente...")
        
        # Obtener gateway y máscara según el SO
        if platform.system() == "Windows":
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            gateway = None
            for line in result.stdout.split('\n'):
                if 'Default Gateway' in line and ':' in line:
                    gateway = line.split(':')[-1].strip()
                    if gateway and gateway != '':
                        break
            # Si no se detecta gateway, usar fallback
            if not gateway:
                gateway = "192.168.1.1"
                print("[!] Gateway no detectado, usando fallback: 192.168.1.1")
        else:
            result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
            gateway = result.stdout.split()[2] if result.returncode == 0 else None
            if not gateway:
                gateway = "192.168.1.1"
                print("[!] Gateway no detectado, usando fallback: 192.168.1.1")
        
        if not gateway:
            print("[ERROR] No se pudo detectar gateway")
            return []
            
        # Determinar rango de red desde gateway
        gateway_parts = gateway.split('.')
        gateway_parts[-1] = '0/24'
        network_range = '.'.join(gateway_parts)
        
        # Fallback a rango común si no se detecta gateway
        if not network_range or '0/24' not in network_range:
            network_range = "192.168.1.0/24"
            print("[!] Usando rango de red por defecto: 192.168.1.0/24")
        
        print(f"[!] Escaneando red: {network_range}")
        
        # Escaneo ARP real
        arp_request = scapy.ARP(pdst=network_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        
        nodes = []
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            
            # Intentar resolver hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Desconocido"
            
            node = {
                "ip": ip,
                "mac": mac,
                "name": hostname,
                "type": "dispositivo",
                "status": "Online",
                "online": True
            }
            nodes.append(node)
        
        print(f"[!] {len(nodes)} dispositivos encontrados")
        network_cache["nodes"] = nodes
        network_cache["last_scan"] = datetime.now().strftime("%H:%M:%S")
        return nodes
        
    except Exception as e:
        print(f"[ERROR] Fallo en escaneo de red: {e}")
        return []


def background_monitor():
    """Mantiene los datos actualizados sin bloquear la web"""
    while True:
        scan_network_real() # Escanea la red
        import time
        time.sleep(60) 


def ia_kernel_engine():
    """
    IA-KERNEL: Agente de Respuesta Autónoma.
    Capacidad: Monitoreo de recursos, detección de intrusos y gestión de archivos.
    """
    print("[IA-KERNEL] Sistema de Decisión Activo.")
    while True:
        try:
            
            cpu_load = psutil.cpu_percent(interval=1)
            mem_load = psutil.virtual_memory().percent
            
           
            if cpu_load > 85 or mem_load > 90:
                print(f"[ALERTA IA] Carga crítica detectada ({cpu_load}%). Buscando anomalías...")
                # Aquí la IA podría tomar la decisión de priorizar procesos de NOVUS
            
           
            global ia_logs
            ia_logs = f"Estado: Nominal | CPU: {cpu_load}% | Nodos: {len(network_cache['nodes'])}"

        except Exception as e:
            print(f"[IA-ERROR] Error en ciclo de pensamiento: {e}")
        
        time.sleep(10)

# =========================
# RUTA DE LOGIN - VERSIÓN DEFINITIVA Y ROBUSTA
# =========================
@app.route('/login', methods=['GET', 'POST'], endpoint='login')
def login():
    """
    FUNCIÓN DE LOGIN DEFINITIVA Y ROBUSTA:
    - Siempre redirige al dashboard después de login exitoso
    - Usa redirección fuerte con code=302
    - Debug completo para troubleshooting
    """
    print(f"[LOGIN] Inicio - Método: {request.method}")
    
    # Si ya está autenticado, redirigir al dashboard
    if current_user.is_authenticated:
        print(f"[LOGIN] Usuario ya autenticado: {current_user.email}")
        return redirect(url_for('dashboard_principal'))

    # Procesar formulario POST
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        print(f"[LOGIN] Intento: {email}")

        # Validar campos
        if not email or not password:
            return render_template('login.html', error="Todos los campos son obligatorios")

        user_data = ds.authenticate_user(email, password)
        if user_data:
            try:
                user = User(
                    id=user_data['id'],
                    email=user_data['email'],
                    role=user_data['role'],
                    sector=user_data['sector'],
                )
                login_user(user, remember=True)
                
                print(f"[LOGIN] ✅ Login exitoso: {user.email}")
                print(f"[LOGIN] current_user.is_authenticated: {current_user.is_authenticated}")
                print(f"[LOGIN] Redirigiendo a dashboard_principal")
                
                # Redirección fuerte al dashboard
                return redirect(url_for('dashboard_principal'), code=302)
                
            except Exception as e:
                print(f"[LOGIN] Error: {e}")
                import traceback
                print(f"[LOGIN] Traceback: {traceback.format_exc()}")
                return render_template('login.html', error="Error al procesar el login")
        else:
            print(f"[LOGIN] ❌ Credenciales incorrectas")
            return render_template('login.html', error="Usuario o contraseña incorrectos")

    # Mostrar formulario (GET)
    return render_template('login.html', error=None)

@app.route('/api/ia/files', methods=['POST'])
def ia_file_manager():
    """
    CAPACIDAD XDR: Permite a la IA o al CEO borrar o analizar archivos/carpetas.
    """
    data = request.json
    accion = data.get('accion')  # 'borrar' o 'analizar'
    ruta_objetivo = data.get('ruta')

    if not ruta_objetivo or not os.path.exists(ruta_objetivo):
        return jsonify({"status": "error", "message": "Ruta no válida o inexistente"}), 400

    try:
        if accion == 'borrar':
            if os.path.isfile(ruta_objetivo):
                os.remove(ruta_objetivo)
            else:
                import shutil
                shutil.rmtree(ruta_objetivo)
            return jsonify({"status": "success", "message": f"Elemento eliminado: {ruta_objetivo}"})

        elif accion == 'analizar':
            analisis = ds.analyze_file(ruta_objetivo)
            return jsonify({
                "status": "success",
                "analisis": analisis
            })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/', endpoint='dashboard_principal')
@app.route('/dashboard', endpoint='dashboard_principal')
@login_required
def dashboard_principal():
    """
    DASHBOARD CON DATOS REALES DEL SISTEMA
    """
    try:
        metricas = ds.get_system_metrics()
        user = ds.get_user_context(current_user)
        print(f"[DASHBOARD] Métricas actualizadas - CPU: {metricas['cpu_load']}%, RAM: {metricas['ram_load']}%")
        return render_template(
            'index.html',
            **metricas,
            user=user,
            siem_enabled=False,
            network_node_count=len(network_cache.get('nodes', [])),
        )
        
    except Exception as e:
        print(f"[ERROR] Dashboard: {e}")
        metricas_fallback = ds.get_system_metrics()
        return render_template(
            'index.html',
            **metricas_fallback,
            user=ds.get_user_context(current_user),
            siem_enabled=False,
            network_node_count=0,
        )

@app.route('/api/dashboard/metrics')
def api_dashboard_metrics():
    metrics = ds.get_system_metrics()
    xdr = ds.get_xdr_data()
    return jsonify({
        "status": "success",
        "nodes": len(network_cache.get("nodes", [])),
        "traffic_mb": metrics.get("network_traffic_mb", 0),
        "threats": len(xdr.get("eventos", [])),
        "endpoints": len(network_cache.get("nodes", [])) or 1,
        "users": metrics.get("usuarios_conectados", 0),
        "cpu": metrics.get("cpu_load", 0),
        "ram": metrics.get("ram_load", 0),
        "health": ds.get_node_health_percent(),
        "timestamp": metrics.get("timestamp_actual"),
    })

@app.route('/vulnerabilidades', endpoint='ruta_vulnerabilidades')
@login_required
def ruta_vulnerabilidades():
    """Vulnerabilidades desde escáner real y base de datos."""
    try:
        vuln_data = ds.get_vulnerabilities_template_data()
        return render_template(
            'vulnerabilidades.html',
            user=ds.get_user_context(current_user),
            **vuln_data,
        )
    except Exception as e:
        print(f"[ERROR] Vulnerabilidades: {e}")
        return render_template(
            'vulnerabilidades.html',
            user=ds.get_user_context(current_user),
            progreso=0,
            realizadas=0,
            objetivo=0,
            total_criticas=0,
            porcentaje_mitigado=0,
            hallazgos=[],
            stats={},
        )

@app.route('/automatizacion', endpoint='ruta_automatizacion')
@login_required
def ruta_automatizacion():
    """
    AUTOMATIZACIÓN CON DATOS 100% REALES
    """
    try:
        # Datos reales del sistema
        procesos = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))
        cpu_total = psutil.cpu_percent(interval=1.0)
        memoria_total = psutil.virtual_memory()
        
        # Reglas basadas en datos reales
        reglas_ia = []
        
        # Regla 1: Control de CPU
        if cpu_total > 60:
            reglas_ia.append({
                "id": "CPU-001",
                "nombre": "Control de procesos CPU",
                "descripcion": f"Detectado uso de CPU al {cpu_total:.1f}%",
                "estado": "Activo",
                "impacto": "Alto",
                "ejecuciones_mes": f"{len([p for p in procesos if p.info.get('cpu_percent', 0) > 50])}"
            })
        
        # Regla 2: Gestión de memoria
        if memoria_total.percent > 70:
            reglas_ia.append({
                "id": "MEM-001", 
                "nombre": "Optimización de memoria",
                "descripcion": f"Memoria al {memoria_total.percent:.1f}%",
                "estado": "Monitoreando",
                "impacto": "Medio",
                "ejecuciones_mes": f"{len([p for p in procesos if p.info.get('memory_percent', 0) > 50])}"
            })
        
        # Regla 3: Procesos críticos
        procesos_criticos = [p for p in procesos if p.info.get('cpu_percent', 0) > 80]
        if procesos_criticos:
            reglas_ia.append({
                "id": "PROC-001",
                "nombre": "Procesos de alto consumo",
                "descripcion": f"{len(procesos_criticos)} procesos críticos detectados",
                "estado": "Alerta",
                "impacto": "Crítico",
                "ejecuciones_mes": str(len(procesos_criticos))
            })
        
        # Estadísticas reales
        stats_auto = {
            "procesos_totales": len(procesos),
            "procesos_criticos": len(procesos_criticos),
            "cpu_actual": f"{cpu_total:.1f}%",
            "memoria_usada": f"{memoria_total.percent:.1f}%",
            "reglas_activas": len(reglas_ia),
            "uptime": f"{(time.time() - psutil.boot_time()) / 3600:.1f} horas"
        }
        
        print(f"[AUTOMATIZACIÓN] {len(reglas_ia)} reglas activas - CPU: {cpu_total}%, RAM: {memoria_total.percent}%")
        
        stats_auto["ejecuciones_mes"] = ds.get_automation_stats(reglas_ia)["ejecuciones_mes"]
        return render_template('automatizacion.html',
                           user=ds.get_user_context(current_user),
                           reglas=reglas_ia,
                           stats=stats_auto)
                           
    except Exception as e:
        print(f"[ERROR] Automatización: {e}")
        return render_template('automatizacion.html',
                           user=ds.get_user_context(current_user),
                           reglas=[],
                           stats={"ejecuciones_mes": 0})

@app.route('/network', endpoint='ruta_network')
@login_required
def ruta_network():
    """Network con dispositivos detectados por escaneo ARP real."""
    try:
        dispositivos_reales = scan_network_real()
        net_stats = psutil.net_io_counters()
        conexiones = len(psutil.net_connections())
        stats_red = {
            "total_nodos": len(dispositivos_reales),
            "nodos_activos": len(dispositivos_reales),
            "ancho_banda": "Sin datos disponibles",
            "trafico_total": f"{round((net_stats.bytes_sent + net_stats.bytes_recv) / (1024**2), 2)} MB",
            "conexiones_activas": conexiones,
            "bytes_enviados": f"{round(net_stats.bytes_sent / (1024**2), 2)} MB",
            "bytes_recibidos": f"{round(net_stats.bytes_recv / (1024**2), 2)} MB",
        }
        return render_template(
            'network.html',
            user=ds.get_user_context(current_user),
            nodos=dispositivos_reales,
            stats=stats_red,
        )
    except Exception as e:
        print(f"[ERROR] Network: {e}")
        return render_template(
            'network.html',
            user=ds.get_user_context(current_user),
            nodos=[],
            stats={"total_nodos": 0, "nodos_activos": 0, "ancho_banda": "Sin datos disponibles", "trafico_total": "0 MB"},
        )

@app.route('/api/ai/command', methods=['POST'])
def ai_command():
    """
    ENDPOINT DE ACCIÓN: Aquí es donde el frontend de Automatización
    envía órdenes reales a la IA-Kernel.
    """
    comando = request.json.get('command')
    target = request.json.get('target')

    
    print(f"[KERNEL] Recibida orden de IA: {comando} sobre {target}")
    
    return jsonify({
        "status": "received",
        "message": f"Comando '{comando}' registrado para revisión en {target or 'nodo local'}",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "nota": "Motor de ejecución autónoma no configurado",
    })

@app.route('/api/network/refresh', methods=['POST'])
def refresh_network():
    """
    Permite forzar un escaneo de red desde el botón del Frontend.
    """
    print("[!] Forzando escaneo de red manual desde el Dashboard...")
    
    threading.Thread(target=scan_network_real).start()
    
    return jsonify({
        "status": "scanning",
        "message": "Escaneo de red iniciado",
    })

@app.route('/registro_empresa', methods=['GET', 'POST'], endpoint='registro_empresa')
def ruta_registro():
    """Registro de empresa persistido en SQLite."""
    config_actual = {
        "nodo_id": ds.get_local_ip(),
        "licencia_status": "Sin datos disponibles",
        "version_kernel": "1.0.4",
        "pyme_mode": True,
        "timestamp_actual": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    if request.method == 'POST':
        nit = request.form.get('nit', '').strip()
        nombre = request.form.get('empresa', request.form.get('razon_social', '')).strip()
        
        if not nit or not nombre:
            return render_template(
                'registro_empresa.html',
                config=config_actual,
                error="NIT y nombre de empresa son obligatorios",
            )

        form_data = {key: request.form.get(key, '').strip() for key in request.form.keys()}
        form_data['nit'] = nit
        form_data['empresa'] = nombre

        if not ds.register_company(form_data, request.remote_addr, request.headers.get('User-Agent', 'Unknown')):
            return render_template(
                'registro_empresa.html',
                config=config_actual,
                error="No se pudo registrar. Verifique que el correo no exista.",
            )

        return redirect(url_for('login'), code=302)

    return render_template('registro_empresa.html', config=config_actual)

@app.route('/incidentes')
@login_required
def ruta_incidentes():
    """Incidentes desde alertas reales en base de datos."""
    data = ds.get_incidents_from_db()
    return render_template(
        'incidentes.html',
        user=ds.get_user_context(current_user),
        incidentes=data['incidentes'],
        total_criticos=data['total_criticos'],
    )

@app.route('/siem', endpoint='ruta_siem')
@app.route('/logs', endpoint='ruta_logs')
@login_required
def ruta_siem():
    """Logs SIEM desde base de datos y conexiones del sistema."""
    logs_reales = ds.get_siem_logs()
    return render_template(
        'siem_dashboard.html',
        user=ds.get_user_context(current_user),
        logs=logs_reales,
    )

@app.route('/endpoints', endpoint='ruta_endpoints_realtime')
@login_required
def ruta_endpoints_realtime():
    """Endpoints detectados por escaneo de red."""
    try:
        endpoints = ds.get_endpoints_from_network(network_cache)
        return render_template(
            'endpoints.html',
            user=ds.get_user_context(current_user),
            endpoints=endpoints,
        )
    except Exception as e:
        print(f"[ERROR] Endpoints: {e}")
        return render_template(
            'endpoints.html',
            user=ds.get_user_context(current_user),
            endpoints=[],
        )

@app.route('/reportes', endpoint='ruta_reportes_realtime')
@login_required
def ruta_reportes_realtime():
    """Reportes agregados desde métricas y base de datos."""
    try:
        report_data = ds.get_report_data(network_cache)
        return render_template(
            'reportes.html',
            user=ds.get_user_context(current_user),
            resumen=report_data['resumen'],
            historial=report_data['historial'],
        )
    except Exception as e:
        print(f"[ERROR] Reportes: {e}")
        return render_template(
            'reportes.html',
            user=ds.get_user_context(current_user),
            resumen={},
            historial=[],
        )

@app.route('/xdr', endpoint='ruta_amenazas_realtime')
@app.route('/amenazas', endpoint='ruta_amenazas_realtime')
@login_required
def ruta_amenazas_realtime():
    """XDR con alertas de base de datos y métricas del sistema."""
    try:
        xdr = ds.get_xdr_data()
        return render_template(
            'xdr.html',
            user=ds.get_user_context(current_user),
            resumen=xdr['resumen'],
            eventos=xdr['eventos'],
            siem_enabled=False,
        )
    except Exception as e:
        print(f"[ERROR] Amenazas: {e}")
        return render_template(
            'xdr.html',
            user=ds.get_user_context(current_user),
            resumen={
                "total_eventos": 0,
                "nivel_critico": 0,
                "salud_nodo": 0,
                "estado": "ERROR",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            eventos=[],
            siem_enabled=False,
        )

@app.route('/api/network/nodes')
def api_network_nodes():
    """
    API REAL - Devuelve dispositivos detectados por escaneo ARP
    """
    try:
        # Obtener dispositivos reales del escaneo
        dispositivos_reales = scan_network_real()
        
        response_data = {
            "status": "success", 
            "nodes": dispositivos_reales
        }
        
        print(f"[API] /api/network/nodes devolviendo: {len(dispositivos_reales)} dispositivos")
        return jsonify(response_data)
        
    except Exception as e:
        print(f"[ERROR] API /api/network/nodes: {e}")
        return jsonify({
            "status": "error", 
            "nodes": []
        })

@app.route('/configuracion')
@login_required
def ruta_configuracion_viva():
    cfg = ds.get_config_data(current_user, app.debug)
    return render_template(
        'configuracion.html',
        user=ds.get_user_context(current_user),
        config=cfg['config'],
        sectores=cfg['sectores'],
        stats=cfg['stats'],
    )

@app.route('/logout', endpoint='logout_seguro')
def logout_seguro():
    """
    LOGOUT FUNCIONAL - Cierra sesión realmente y redirige al login
    """
    try:
        # 1. LOG DE SEGURIDAD
        if current_user.is_authenticated:
            print(f"LOG: Sesión cerrada para el usuario {current_user.email}")
        else:
            print("LOG: Intento de logout sin usuario autenticado")
        
        # 2. CERRAR SESIÓN REALMENTE
        logout_user()
        
        # 3. REDIRIGIR AL LOGIN
        print("LOG: Redirigiendo a página de login")
        return redirect(url_for('login'))
        
    except Exception as e:
        print(f"ERROR en logout: {e}")
        return redirect(url_for('login'))

@app.route('/<path:endpoint>')
def gateway_modulos(endpoint):
    """
    GATEWAY DE SEGURIDAD:
    Esta ruta captura cualquier intento de navegación y lo resuelve 
    contra la carpeta de templates de forma inteligente.
    """
    
    resource_name = endpoint.replace('.html', '')
    
    
    target_file = f"{resource_name}.html"
    file_path = os.path.join(app.template_folder, target_file)

    
    if os.path.exists(file_path):
        
        return render_template(target_file)
    else:
        
        print(f"[ALERTA] Intento de acceso a módulo inexistente: {endpoint}")
        return jsonify({
            "status": "error",
            "message": f"Módulo '{resource_name}' no inicializado",
            "node": ds.get_local_ip(),
        }), 404


ds.init_app_data()
threading.Thread(target=background_monitor, daemon=True).start()
threading.Thread(target=ia_kernel_engine, daemon=True).start()

if __name__ == '__main__':
    print("\n[!] =========================================")
    print("[!] NODO CALI: KERNEL NOVUS DESPLEGADO")
    print("[!] ESPERANDO CONEXIONES EN EL PUERTO 5000")
    print("[!] =========================================\n")
    app.run(debug=True, host='0.0.0.0', port=5000)