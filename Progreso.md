# Construyendo un Firewall Inteligente para el Edge: Avances y Decisiones

¡Hola a todos! Si están leyendo esto, es porque quieren saber cómo estamos armando nuestro firewall inteligente. La idea no es hacer un firewall aburrido que solo bloquee el puerto 80 porque sí, sino dotarlo de un "cerebro" capaz de detectar comportamientos maliciosos (como escaneos de red y ráfagas de paquetes) en tiempo real.

Aquí les cuento qué hemos construido, la arquitectura completa (desde la captura de paquetes hasta la Inteligencia Artificial), por qué elegimos estas tecnologías y cómo encajan todas las piezas.

---

## 1. Arquitectura del Sistema: ¿Qué tenemos desarrollado hasta ahora?

El proyecto se divide en módulos muy claros para asegurar escalabilidad y facilitar el mantenimiento. Todo esto ya está funcional:

### A. La Captura de Datos (El Oído)
1. **Sniffer / Capturador (`sniffer_base.py`):** Interactúa directamente con la interfaz de red para capturar paquetes crudos y extraer información a nivel de enlace, red y transporte.
2. **Gestor de Flujos (`flow_table.py`):** Agrupa lógicamente los paquetes individuales en "flujos de comunicación bidireccionales", dándonos el contexto completo de una conexión a lo largo del tiempo.
3. **Extractor de Características (`extractor_vect.py`):** Procesa los datos de cada flujo cerrado y calcula propiedades matemáticas y estadísticas para generar el vector final de 9 variables.

### B. El Análisis con IA (El Cerebro)
1. **Pipeline de Entrenamiento (`train_edge_model.py`):** Entrena un modelo LightGBM usando millones de conexiones reales para que aprenda a distinguir tráfico legítimo de ataques.
2. **Exportación Universal (`ONNX`):** Empaqueta el modelo en un archivo ultraligero (`firewall_edge_model.onnx` de ~110 KB), listo para producción sin dependencias pesadas.
3. **Sistema de Evaluación (`evaluate_onnx_model.py`):** Valida el modelo. Logramos detectar el **99.54% de Port Scans** y el **99.64% de DDoS (ráfagas)** en tráfico nuevo de prueba.

---

## 2. La Lógica: ¿Cómo funciona y cómo lo integraremos?

Un error común al meter Inteligencia Artificial en seguridad es creer que el modelo debe bloquear directamente el tráfico. ¡Falso! Si hacemos eso, el inevitable 1% de error (falsos positivos) terminará bloqueando a usuarios legítimos a la primera conexión. Nuestra lógica separa la extracción matemática, el análisis de IA y el castigo.

```mermaid
flowchart TD
    A[Tráfico de Red Entrante] --> B{sniffer_base.py<br>Captura Cruda}
    B --> C(flow_table.py<br>Agrupación Bidireccional)
    C --> D(extractor_vect.py<br>Calcula 9 variables matemáticas)
    
    subgraph cerebro [El Cerebro - Análisis]
        D --> E(Modelo ONNX Runtime)
        E -->|¿Es ataque?| F{Evaluación de Umbral}
    end
    
    F -->|"Menos de 20 alertas"| G[Ignorar / Falso Positivo]
    F -->|"Más de 20 alertas<br>en < 5 segundos"| H[Sentencia: IP Maliciosa]
    
    subgraph verdugo [El Verdugo - Ejecución]
        H --> I[(nftables: Blacklist Dinámica)]
        I --> J[Tráfico de IP bloqueado a nivel Kernel]
    end
    
    style E fill:#f9f,stroke:#333,stroke-width:2px
    style I fill:#ff6666,stroke:#333,stroke-width:2px
```

*(El modelo actúa como un radar. Si pita 1 vez, lo anotamos. Si pita 20 veces, el Daemon dicta sentencia y `nftables` ejecuta el bloqueo a velocidad del kernel).*

---

## 3. Justificación Tecnológica (¿Por qué usamos lo que usamos?)

Cuando diseñas algo para el "Edge" (dispositivos de hardware limitados), cada decisión cuenta. Aquí el porqué de nuestras tecnologías:

### A. Captura de Tráfico (Raw Sockets vs. Scapy)
*   **Por qué NO Scapy:** Aunque es genial y fácil de usar, es muy pesado e introduce demasiada latencia para un entorno de producción en tiempo real.
*   **Por qué SÍ Raw Sockets:** Usar `socket.AF_PACKET` y `struct.unpack` nativos en Python garantiza captura y desempaquetado a nivel de bytes con un rendimiento brutal.

### B. Gestión de Memoria y Flujos (Evitando Memory Leaks)
*   **Bidireccionalidad:** Ordenamos IPs y Puertos (menor a mayor) antes de generar la clave para analizar peticiones (cliente->servidor) y respuestas (servidor->cliente) juntas.
*   **Gestión de RAM:** Usamos umbrales de inactividad (`timeout`), un límite máximo de paquetes por flujo y cierres forzados al detectar banderas `FIN` o `RST`. Esto procesa el tráfico en "chunks" ligeros y evita fugas de memoria al no mantener conexiones zombis abiertas indefinidamente.

### C. La Magia Matemática (Varianza y Entropía de Shannon)
*   **Varianza (Tiempos y Tamaños):** Ataques automatizados (como hping3 o SYN Flood) envían ráfagas repetitivas a intervalos exactos y tamaños idénticos (varianza casi 0). El usuario legítimo es caótico.
*   **Entropía de Shannon (Puertos y Banderas):** Un escáner probará puertos secuencialmente, generando muchísima entropía (información muy variada). Una conexión normal a YouTube interactúa repetitivamente con el puerto 443 (entropía muy baja). ¡Matemáticas puras para atrapar atacantes!

### D. Inteligencia Artificial (LightGBM y ONNX)
*   **LightGBM en lugar de Deep Learning:** Las redes neuronales son lentas y glotonas. LightGBM (árboles de decisión) es ultrarrápido y extremadamente preciso para datos tabulares (las 9 columnas matemáticas).
*   **ONNX Runtime:** Nos permite tirar dependencias pesadas como Pandas o Scikit-Learn en producción. El firewall ejecuta el modelo en un motor C++/Rust súper optimizado.

### E. Ejecución de Bloqueos (`nftables`)
*   **Por qué NO iptables:** Revisa reglas de forma secuencial (muy lento si tu blacklist crece).
*   **Por qué SÍ nftables:** Usa "sets" (hash tables) que verifican si una IP está bloqueada de forma instantánea, sin importar cuántas IPs haya. Perfecto para blacklists temporales.

---

## Siguientes Pasos
Ya tenemos la extracción matemática (`extractor_vect.py`) funcionando para TCP/IPv4 y nuestro cerebro artificial (`.onnx`) bien entrenado. Nuestro próximo hito es conectar los cables: lograr que el extractor pase los vectores en vivo a ONNX y construir el disparador que envíe los castigos a `nftables`. Adicionalmente, buscaremos expandir la visibilidad hacia protocolos como UDP e ICMP. ¡Ya casi está!
