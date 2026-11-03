# Laboratorio virtualizado de Jagi-Sentinel (Fase III)

Red Docker aislada 192.168.56.0/24 con tres dispositivos IoT simulados.
Contiene servicios deliberadamente vulnerables: usar solo en este equipo.

| Dispositivo        | IP            | Servicios                        | Vulnerabilidades |
|--------------------|---------------|----------------------------------|------------------|
| Gateway (este PC)  | 192.168.56.1  | -                                | -                |
| Camara IP simulada | 192.168.56.10 | Telnet 23, HTTP 80 (admin/admin) | V-01, V-02, V-04 |
| Impresora simulada | 192.168.56.20 | Apache 2.4.49 en el 80           | V-03             |
| Sensor/NAS simulado| 192.168.56.30 | FTP 21 (anonimo)                 | V-05             |

## Levantar
    sudo docker compose up -d --build
    sudo docker compose ps

## Apagar
    sudo docker compose down
