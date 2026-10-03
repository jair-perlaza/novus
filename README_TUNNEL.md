# NOVUS PLATFORM - ACCESO EXTERNO PARA SOCIOS

## 📋 INFORMACIÓN DE ACCESO ACTUAL

### 🌐 URLs del Sistema
- **IP Local**: `10.177.141.166`
- **URL Local**: `http://localhost:8000`
- **URL Red Local**: `http://10.177.141.166:8000`

### 🔐 Credenciales para Socios

#### 🏦 SECTOR FINTECH
- **CISO**: `ciso@novus.local` / `CISO!FINTECH#2026`
- **CTO**: `cto@novus.local` / `CTO!FINTECH#2026`

#### 🚛 SECTOR LOGÍSTICA/MOVILIDAD
- **CPO**: `cpo@novus.local` / `CPO!LOGISTICA#2026`
- **CSO**: `cso@novus.local` / `CSO!LOGISTICA#2026`

### 🔗 Enlaces del Sistema
- **Principal**: `http://localhost:8000/`
- **Login Sectorial**: `http://localhost:8000/sector-login`
- **Panel Pruebas**: `http://localhost:8000/test-sector-auth`

---

## 🚀 OPCIONES PARA ACCESO EXTERNO (Túneles)

### 1️⃣ NGROK (Recomendado - Registro Gratuito)
```bash
# 1. Descargar ngrok para Windows
# https://ngrok.com/download

# 2. Registrarse gratis
# https://ngrok.com/signup

# 3. Obtener authtoken
# https://dashboard.ngrok.com/get-started/your-authtoken

# 4. Configurar
ngrok config add-authtoken TU_TOKEN

# 5. Ejecutar túnel
ngrok http 8000
```

### 2️⃣ LOCALXPOSE (Gratis sin Registro)
```bash
# 1. Descargar localxpose
# https://localxpose.io/downloads

# 2. Ejecutar túnel
loclx tunnel 8000
```

### 3️⃣ CLOUDFLARED (Requiere Registro)
```bash
# 1. Descargar cloudflared
# https://github.com/cloudflare/cloudflared/releases

# 2. Ejecutar túnel
cloudflared tunnel --url http://localhost:8000
```

### 4️⃣ SERVEO (Gratis con SSH)
```bash
# Requiere SSH instalado
ssh -R 80:localhost:8000 serveo.net
```

### 5️⃣ LOCALHOST.RUN (Gratis con SSH)
```bash
# Requiere SSH instalado
ssh -R 80:localhost:8000 localhost.run
```

---

## 🛡️ CARACTERÍSTICAS DE SEGURIDAD IMPLEMENTADAS

- ✅ **Validación de Dispositivo**: Cada usuario está vinculado a un dispositivo específico con fingerprinting único
- ✅ **Aislamiento de Sector**: Acceso exclusivo por sector con usuarios predefinidos
- ✅ **Alertas en Tiempo Real**: Generación automática de alertas críticas para accesos no autorizados
- ✅ **Registro Completo**: Auditoría detallada de todos los intentos de acceso
- ✅ **Sesión Segura**: Monitoreo constante y cierre automático por inactividad

---

## 📱 PASOS PARA COMPARTIR CON SOCIOS

1. **Elegir una opción de túnel** (recomiendo ngrok)
2. **Crear el túnel** siguiendo las instrucciones
3. **Copiar la URL pública** generada
4. **Compartir la URL** con CISO, CTO, CPO, CSO
5. **Enviar las credenciales** correspondientes a cada sector

---

## ⚠️ INSTRUCCIONES IMPORTANTES

- Comparte la URL pública solo con personal autorizado
- La URL puede cambiar cada vez que inicies el túnel
- Mantén la ventana del túnel abierta para mantener el acceso activo
- Monitorea los logs de seguridad regularmente

---

## 🔄 ESTADO ACTUAL DEL SERVIDOR

- ✅ Servidor NOVUS corriendo en puerto 8000
- ✅ Sistema de autenticación sectorial activo
- ✅ Base de datos inicializada
- ✅ Validación de dispositivo implementada
- ⏳ Esperando túnel público para acceso externo
