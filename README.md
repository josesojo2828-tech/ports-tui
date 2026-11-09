# ports-tui

Responde una sola pregunta, que suele ser la que importa: **¿qué puertos están
realmente expuestos en esta máquina?**

Cruza los sockets que están escuchando (`/proc`) con las reglas de UFW y
clasifica cada puerto según su exposición real, no según lo que uno cree que
configuró.

## Qué muestra

| Estado | Significado |
|---|---|
| `expuesto` | Hay una regla ALLOW desde cualquier origen |
| `restringido` | Hay una regla ALLOW solo desde una red concreta |
| `bloqueado` | Una regla DENY/REJECT lo bloquea |
| `bloqueado_por_defecto` | Lo cubre la política por defecto (`deny`) |
| `permitido_por_defecto` | Lo cubre la política por defecto (`allow`) |
| `sin_firewall` | UFW está inactivo |
| `local` | El socket solo escucha en loopback |

Cada puerto lleva un nivel de severidad, así que lo realmente peligroso queda
arriba sin tener que leer 40 reglas.

## Arquitectura

```
┌─────────────────┐   HTTPS + Bearer token   ┌──────────────────┐
│  TUI (usuario)  │ ───────────────────────▶ │  daemon (root)   │
└─────────────────┘                          └────────┬─────────┘
                                                      │
                                    ┌─────────────────┼─────────────────┐
                                    ▼                 ▼                 ▼
                               /proc/net          ufw status       audit log
```

- El **daemon** corre como root porque necesita leer `/proc` y ejecutar `ufw`.
- La **TUI** corre como usuario normal y habla con el daemon por HTTPS con un
  token Bearer. Nunca toca el firewall directamente.
- El token se guarda **hasheado** (SHA-256) en `/etc/ports-tui/token.hash`.
- Cada acción queda registrada en un audit log JSONL.

## Instalación

```bash
make build
```

## Inicio rápido

```bash
# 1. Generar el token (y guardar el hash del daemon)
sudo ./bin/ports-tui token generate --daemon

# 2. Certificado TLS auto-firmado
sudo ./bin/ports-tui tls ensure

# 3. Levantar el daemon: API + dashboard web sobre TLS
sudo ./bin/ports-tui serve
#    https://127.0.0.1:9443

# 4. Abrir la TUI (otra terminal, sin privilegios)
./bin/ports-tui
```

Para probar sin riesgo sobre el firewall real:

```bash
sudo ./bin/ports-tui serve --demo
```

## Comandos

```
ports-tui [flags]              Abre la TUI (equivale a "ports-tui tui")
ports-tui serve [flags]        Levanta el daemon (API REST + dashboard web)
ports-tui token <sub> [flags]  generate | show | rotate
ports-tui tls ensure [flags]   Genera el certificado TLS auto-firmado
ports-tui doctor [flags]       Diagnostica el entorno
ports-tui version              Muestra la versión
```

Flags útiles del daemon: `--addr`, `--config`, `--token-file`, `--tls-cert`,
`--tls-key`, `--audit-log`, `--cors-origin`, `--demo`.

## Tests

```bash
make test
```

Los tests cubren el parseo de `ufw status`, el análisis de exposición y la API,
usando un backend de UFW simulado. No requieren root ni tocar el firewall.

## Seguridad

- Escucha **solo en loopback** por defecto (`127.0.0.1:9443`).
- TLS obligatorio (auto-firmado si no configurás otro).
- Token con hash SHA-256; el texto plano solo vive del lado del cliente.
- Configuración `0600` en `/etc/ports-tui`.
