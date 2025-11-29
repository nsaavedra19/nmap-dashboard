# Línea 1:
import streamlit as st
# Línea 2:
import pandas as pd
# Línea 3:
import re
# Línea 4:
from io import StringIO
# Línea 5:
import math

# Línea 6:
# --- Constantes y Fórmulas CVSS 3.1 ---
# Línea 7:
# Estas son constantes necesarias para calcular la puntuación base.
# Línea 8:
CONST_SCOPE_IMPACT = 1.08 # Multiplicador para Scope Changed
# Línea 9:
CVSS_SCORES = {
# Línea 10:    
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}, # Attack Vector
# Línea 11:    
    'AC': {'H': 0.44, 'L': 0.77}, # Attack Complexity
# Línea 12:    
    'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27}, # Privileges Required (Scope Unchanged)
# Línea 13:    
    'PR_S': {'N': 0.85, 'L': 0.68, 'H': 0.50}, # Privileges Required (Scope Changed)
# Línea 14:    
    'UI': {'N': 0.85, 'R': 0.62}, # User Interaction
# Línea 15:    
    'C': {'N': 0.00, 'L': 0.22, 'H': 0.56}, # Confidentiality
# Línea 16:    
    'I': {'N': 0.00, 'L': 0.22, 'H': 0.56}, # Integrity
# Línea 17:    
    'A': {'N': 0.00, 'L': 0.22, 'H': 0.56}, # Availability
# Línea 18:
}
# Línea 19:

# Línea 20: --- Base de Datos Estática de Vulnerabilidades (con CVSS Vector) ---
# Línea 21:
# { "servicio versión": {"desc": "Descripción", "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"} }
# Línea 22:
VULNERABILIDADES_ALTAS = {
# Línea 23:    
    "vsftpd 2.3.4": {
        "desc": "Backdoor intencional (CVE-2011-0762).", 
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
# Línea 24:
    "openssh 7.7": {
        "desc": "Múltiples vulnerabilidades de enumeración de usuarios.",
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
# Línea 25:
    "apache 2.2.8": {
        "desc": "Vulnerabilidad crítica de desbordamiento de búfer. Ya no soportado.",
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
# Línea 26:
    "nginx 1.14.0": {
        "desc": "Vulnerabilidad de lectura de memoria (CVE-2018-16162).",
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    },
# Línea 27:
    "microsoft-ds": {
        "desc": "Servicio SMB/Samba abierto y sin parche (ej. EternalBlue/WannaCry).",
        "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    },
# Línea 28:
}

# Línea 29:
# --- Función de Cálculo CVSS 3.1 ---
# Línea 30:
def calcular_cvss_31(vector_string):
# Línea 31:
    """Calcula el puntaje base CVSS 3.1 a partir de un vector."""
    
    # Valores por defecto para el impacto si no se encuentra el vector
    if not vector_string:
        return 0.0
        
    metricas = {}
    for par in vector_string.split('/'):
        if ':' in par:
            k, v = par.split(':')
            metricas[k] = v

    # 1. Componentes de Impacto (Impact Sub-Score, IS)
    isc_base = 1 - (
        (1 - CVSS_SCORES['C'][metricas.get('C', 'N')]) * (1 - CVSS_SCORES['I'][metricas.get('I', 'N')]) * (1 - CVSS_SCORES['A'][metricas.get('A', 'N')])
    )
    
    sc = metricas.get('S', 'U') # Scope
    
    if sc == 'U': # Scope Unchanged
        isc = 6.42 * isc_base
        if isc <= 0:
            impact = 0
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else: # Scope Changed
        isc = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        if isc <= 0:
            impact = 0
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15

    # Para ser estrictos con la fórmula de NVD:
    if isc <= 0.02:
        impact = 0.0

    # 2. Componentes Explotables (Exploitability Sub-Score, ES)
    es = (
        8.22 * CVSS_SCORES['AV'][metricas.get('AV', 'N')] * CVSS_SCORES['AC'][metricas.get('AC', 'L')] * CVSS_SCORES['UI'][metricas.get('UI', 'N')]
    )
    
    # PR depende del Scope
    pr_metric = 'PR_S' if sc == 'C' else 'PR'
    es *= CVSS_SCORES[pr_metric][metricas.get('PR', 'N')]

    # 3. Cálculo del Puntaje Base (Base Score)
    if impact <= 0:
        base_score = 0.0
    elif sc == 'U': # Scope Unchanged
        base_score = round(min((es + impact), 10.0) * 10, 0) / 10
    else: # Scope Changed
        base_score = round(min((es + impact) * CONST_SCOPE_IMPACT, 10.0) * 10, 0) / 10

    return base_score
# Línea 61:
# --- 2. Lógica de Clasificación de Riesgo ACTUALIZADA con CVSS ---
# Línea 62:
def clasificar_riesgo(puerto, servicio, version=""):
# Línea 63:
    """Clasifica el riesgo y calcula CVSS 3.1 si la versión es vulnerable."""
    
    puerto = int(puerto)
    servicio = servicio.lower().strip()
    version = version.lower().strip()
    
    riesgo = "Bajo"
    descripcion = "Sin problemas de riesgo inmediato o conocido."
    cvss_score = 0.0
    cvss_vector = "N/A"
    
    # 1. Búsqueda de Vulnerabilidades por Versión (Prioridad Máxima)
    servicio_version = f"{servicio} {version}".strip()
    
    for clave_vuln, data_vuln in VULNERABILIDADES_ALTAS.items():
        if clave_vuln in servicio_version:
            cvss_vector = data_vuln['vector']
            cvss_score = calcular_cvss_31(cvss_vector)
            riesgo = "Alto" if cvss_score >= 7.0 else "Medio"
            descripcion = f"VULNERABLE (CVSS {cvss_score:.1f}): {data_vuln['desc']}"
            return riesgo, descripcion, cvss_score, cvss_vector
            
    # 2. Puertos/Servicios de Alto Riesgo (Sin CVSS)
    puertos_alto_riesgo = {21: "FTP", 23: "Telnet", 445: "SMB"}
    if puerto in puertos_alto_riesgo or "microsoft-ds" in servicio:
        riesgo = "Alto"
        descripcion = f"Puerto/Servicio: {puertos_alto_riesgo.get(puerto, servicio)} sin cifrar o con vulnerabilidades históricas (requiere revisión)."
        return riesgo, descripcion, cvss_score, cvss_vector
        
    # 3. Servicios de Riesgo Medio (Administración remota)
    servicios_medio_riesgo = {"ssh", "rdp", "vnc", "mysql", "postgresql"}
    if servicio in servicios_medio_riesgo and not version:
        riesgo = "Medio"
        descripcion = f"Servicio de administración ({servicio}) detectado. El riesgo depende de la configuración (parches y contraseñas)."
        return riesgo, descripcion, cvss_score, cvss_vector
        
    # 4. Otros (Bajo Riesgo)
    return riesgo, descripcion, cvss_score, cvss_vector


# Línea 96:
# --- 3. Función de Procesamiento: Salida Estándar Nmap ---
# Línea 97:
def procesar_nmap_salida_estandar(texto_plano_content):
    hallazgos = []
    
    patron_host = re.compile(
        r'Nmap scan report for (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    )
    
    patron_puerto = re.compile(
        r'(\d+)/(tcp|udp)\s+open\s+([\w-]+)\s*(.*)'
    )

    current_ip = 'N/A'

    for linea in texto_plano_content.split('\n'):
        
        match_host = patron_host.search(linea)
        if match_host:
            current_ip = match_host.group('ip')
            continue 
        
        match_puerto = patron_puerto.search(linea)
        if match_puerto:
            puerto = match_puerto.group(1)
            protocolo = match_puerto.group(2)
            servicio = match_puerto.group(3).strip()
            version = match_puerto.group(4).strip()
            
            # Clasificar y obtener el detalle del riesgo y CVSS
            nivel_riesgo, descripcion_riesgo, cvss_score, cvss_vector = clasificar_riesgo(puerto, servicio, version)

            hallazgos.append({
                "IP": current_ip,
                "Puerto": int(puerto),
                "Protocolo": protocolo,
                "Servicio": servicio,
                "Versión": version,
                "Riesgo": nivel_riesgo,
                "CVSS Score": f"{cvss_score:.1f}" if cvss_score > 0 else "N/A",
                "CVSS Vector": cvss_vector,
                "Detalle del Riesgo": descripcion_riesgo
            })

    return pd.DataFrame(hallazgos)
# Línea 126:
# --- 4. Script Principal de Streamlit ---
# Línea 127:
def main():
# Línea 128:
    st.set_page_config(layout="wide", page_title="Nmap Risk Dashboard - CVSS")
# Línea 129:
    st.title("-------------------EMPRESA SECURECORP-------------------")
    st.title("ANÁLISIS DE VULNERABILIDADES CON INTELIGENCIA ARTIFICIAL")
    st.markdown("NOMBRE COMPLETO:NATANIEL ENRRIQUE SAAVEDRA QUESPIA")
    st.markdown("CÓDIGO DE ESTUDIANTE: 99098")
    st.markdown("FECHA DE PRESENTACIÓN: 28/11/2025")

    st.title("🛡️ Dashboard de Análisis de Riesgos de Nmap (con CVSS 3.1)")
# Línea 130:
    st.markdown("Analiza la salida estándar de Nmap, calculando el puntaje **CVSS 3.1** para vulnerabilidades conocidas.")

    nmap_output = st.text_area(
        "1. Pega aquí el resultado de Nmap en formato de Salida Estándar:",
        height=300,
        placeholder="Ejecuta: nmap -sC -sV <IP_o_RANGO> y pega la salida completa de la consola aquí."
    )

    if nmap_output:
        st.info("Procesando datos, calculando CVSS 3.1...")
        
        df_resultados = procesar_nmap_salida_estandar(nmap_output) 
        
        if df_resultados.empty:
            st.warning("No se pudieron extraer puertos abiertos. Asegúrate de usar las opciones '-sV' y '-sC' en Nmap para obtener información de versión.")
            return

        # ----------------------------------------------------
        # Visualización de Resultados
        # ----------------------------------------------------
        
        st.header("2. Resultados del Análisis")
        
        # Conteo y Gráfico
        conteo_riesgos = df_resultados['Riesgo'].value_counts().reindex(
            ['Alto', 'Medio', 'Bajo'], fill_value=0
        )
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            st.subheader("Resumen de Riesgos")
            st.metric("Total de Puertos Analizados", len(df_resultados))
            st.dataframe(conteo_riesgos.rename("Cantidad"))
        
        with col2:
            st.subheader("Distribución Gráfica")
            color_map = {'Alto': '#E91E63', 'Medio': '#FFC107', 'Bajo': '#4CAF50'}
            
            df_chart = pd.DataFrame({
                'Riesgo': conteo_riesgos.index,
                'Cantidad': conteo_riesgos.values,
                'Color': [color_map.get(r, '#808080') for r in conteo_riesgos.index]
            })

            st.bar_chart(
                df_chart.set_index('Riesgo'), 
                y='Cantidad', 
                color='Color', 
                use_container_width=True
            )

        # Tabla Detallada
        st.subheader("3. Detalle Completo de Hallazgos")
        
        # Función de estilo para resaltar el riesgo
        def highlight_riesgo(s):
            color = ''
            if s['Riesgo'] == 'Alto':
                color = '#ffdddd'  # Rojo claro
            elif s['Riesgo'] == 'Medio':
                color = '#fffacd'  # Amarillo claro
            else:
                color = '#ddffdd'  # Verde claro
            return [f'background-color: {color}'] * len(s)
        
        st.dataframe(
            df_resultados.style.apply(highlight_riesgo, axis=1), 
            use_container_width=True
        )

# Ejecutar la función principal
if __name__ == '__main__':

    main()

