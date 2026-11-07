# kaira-uptime-probe

Sonda externa (anillo B) del sistema de monitoreo de mykaira.ai. Corre en GitHub Actions cada 5 minutos, fuera de AWS:

- `GET https://mykaira.ai/api/health?mode=live`, con 3 reintentos.
- Latido del vigilante interno (`kaira-sentinel`).
- Días que le quedan al certificado TLS.
- Si el servidor no responde a nivel de red, reinicia la instancia EC2 (usuario IAM que solo puede reiniciar esa instancia, como máximo una vez por hora) y verifica que volvió.
- Avisa por WhatsApp (Twilio) y escala si no logra recuperarlo.

Sin secretos en el código: todo vive en los secretos de Actions. El código fuente y la documentación canónica están en el repo privado `aion-kaira` (`infra/monitoring/`, `docs/operations/MONITORING_SYSTEM.md`). Este repo es una copia de despliegue.
