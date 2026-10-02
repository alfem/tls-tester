# tls-tester — Servidor de diagnóstico TLS/mTLS

Herramienta de diagnóstico que se levanta **en lugar del servidor web** y espera conexiones de cliente para volcar toda la información sobre cada petición: parámetros TLS negociados, certificado de cliente (hoja + cadena), cabeceras HTTP, variables de entorno, etc. También diagnostica de forma estructurada los **fallos de handshake TLS** (certificados, CAs, alertas), lo que la hace especialmente útil para averiguar por qué una conexión mTLS que pasa por un **WAF/proxy corporativo** falla mientras que el acceso directo al origen funciona.

## Modos de ejecución

| Modo | Opciones | Qué solicita y valida |
|---|---|---|
| mTLS estricto (por defecto) | `--ca-cert ca.pem` | REQUIERE certificado de cliente y lo valida contra `--ca-cert` |
| HTTPS + cliente opcional | `--no-mtls --ca-cert ca.pem` | Solicita certificado de cliente (opcional) y lo **valida si se presenta** |
| HTTPS simple | `--no-mtls` (sin `--ca-cert`) | No solicita certificado de cliente |
| HTTP plano | `--http` | Sin TLS (para pruebas detrás de proxies que terminan SSL) |

En modo mTLS con `--ca-cert`, el certificado del cliente se verifica además con `openssl verify -CAfile ... -purpose sslclient` y se muestra el veredicto en la salida.

## Procedimiento de diagnóstico WAF → origen (mTLS)

Escenario: navegador → origen **funciona**; navegador externo → WAF corporativo → origen **falla**.

1. Levanta la herramienta en el origen, con el certificado de servidor real y la CA que debe emitir el certificado de cliente del WAF:

   ```
   python tls-tester --port 8443 \
       --cert server.pem --key server.key \
       --ca-cert ca-del-waf.pem \
       --handshake-timeout 15 --output-dir ./logs
   ```

   En el arranque la herramienta muestra su **propio certificado de servidor** (subject, issuer, SANs, SHA256 — el WAF debe confiar en su CA) y las **CAs del bundle** contra el que validará al WAF.

2. Conecta vía el WAF (o pide a un usuario externo que acceda). Cada intento de conexión produce un informe:
   - Handshake con éxito → volcado completo: certificado del cliente (el del WAF), cadena, veredicto `openssl verify`, cabeceras HTTP (incluidas las que inyecte el WAF).
   - Handshake fallido → informe `FALLO DE HANDSHAKE TLS` con quién rechazó, alerta, certificado rechazado (capturado si Python ≥ 3.10) y veredicto `openssl verify`. Con `--output-dir` se guarda `handshake_error_NNNN.json`.

3. Interpreta el resultado:

| Qué muestra la herramienta | Causa más probable |
|---|---|
| `Quien rechazo: servidor`, verify_code 20 (`unable to get local issuer certificate`) | La CA del certificado que presenta el WAF **no está en `--ca-cert`**, o el WAF no envía los intermedios de su cadena |
| `Quien rechazo: servidor`, verify_code 18/19 (autofirmado) | El WAF presenta un certificado autofirmado o no emitido por la CA esperada |
| `Quien rechazo: servidor`, verify_code 10 (expirado) / 9 (aún no válido) | El certificado del WAF está expirado o aún no es válido |
| `Quien rechazo: servidor`, "no presentó ninguno" (`peer did not return a certificate`) | El WAF **no está configurado para presentar certificado de cliente** hacia este origen (perfil mTLS ausente) |
| `Quien rechazo: cliente`, alerta `unknown ca` / `certificate unknown` | El **WAF rechaza el certificado de servidor** de la herramienta: no confía en su CA. Instala la CA del servidor en el almacén de confianza del WAF o usa un certificado emitido por la CA corporativa (`--cert`/`--key`) |
| TIMEOUT | WAF colgado, firewall, red/MTU, o cliente que conecta sin hablar TLS |
| Desajuste de ciphers / versión | El WAF exige suites o versiones TLS distintas para este origen |

Regla general: **directo OK + vía WAF FAIL ⇒ normalmente la CA del WAF no está en `--ca-cert`, o el certificado de servidor no es de confianza para el WAF, o la cadena del WAF está incompleta.**

## Recetas openssl de prueba

```bash
# CA1 (de confianza) y CA2 (ajena)
openssl req -x509 -newkey rsa:2048 -keyout ca1.key -out ca1.crt -days 365 -nodes -subj '/CN=Test CA1'
openssl req -x509 -newkey rsa:2048 -keyout ca2.key -out ca2.crt -days 365 -nodes -subj '/CN=Test CA2'

# Certificado de servidor firmado por CA1 (con SAN)
openssl req -newkey rsa:2048 -keyout srv.key -out srv.csr -nodes -subj '/CN=server.local'
openssl x509 -req -in srv.csr -CA ca1.crt -CAkey ca1.key -CAcreateserial -out srv.crt -days 365 \
  -extfile <(printf 'subjectAltName=DNS:localhost,DNS:server.local\nextendedKeyUsage=serverAuth')

# Cliente "bueno" (CA1, clientAuth)
openssl req -newkey rsa:2048 -keyout cli1.key -out cli1.csr -nodes -subj '/CN=WAF-bueno/O=WAF'
openssl x509 -req -in cli1.csr -CA ca1.crt -CAkey ca1.key -CAcreateserial -out cli1.crt -days 365 \
  -extfile <(printf 'extendedKeyUsage=clientAuth')

# Cliente "malo" (CA2) — mismo proceso con ca2.crt/ca2.key
# Cliente autofirmado
openssl req -x509 -newkey rsa:2048 -keyout cli-self.key -out cli-self.crt -days 365 -nodes -subj '/CN=WAF-self'

# Servidor con mTLS
python3 tls-tester --port 8443 --cert srv.crt --key srv.key --ca-cert ca1.crt --output-dir ./logs

# Éxito
curl -k --cert cli1.crt --key cli1.key https://localhost:8443/
# Certificado rechazado (CA ajena)
curl -k --cert cli2.crt --key cli2.key https://localhost:8443/
# Sin certificado
curl -k https://localhost:8443/
# Cliente rechaza el certificado de servidor (WAF que no confía en la CA)
openssl s_client -connect localhost:8443 -CAfile ca2.crt -verify_return_error \
  -cert cli1.crt -key cli1.key
# Cliente mudo (timeout)
nc localhost 8443
```

## Salidas

- **stdout** — informes de cada petición y de cada fallo de handshake.
- **HTTP/HTML** — cada petición exitosa responde con una página de diagnóstico.
- **JSON** — con `--output-dir`: `request_NNNN.json` (peticiones) y `handshake_error_NNNN.json` (fallos de handshake).

## Limitaciones por versión de Python

- **Python 3.10+**: captura completa del certificado rechazado (hoja y, si llega, cadena) incluso cuando el handshake falla.
- **Python 3.6–3.9 / 2.7**: el certificado rechazado no puede capturarse tras el fallo (limitación de CPython); el informe incluye igualmente el código de verificación (`verify_code`), el mensaje y la interpretación de la alerta.
- Python 3.7+ añade `verify_code`/`verify_message` a la excepción (`SSLCertVerificationError`).

## Requisitos

- Python 2.7.9+ o 3.6+ (recomendado 3.10+ para el diagnóstico completo de fallos).
- `openssl` CLI en el PATH (verificación de certificados, generación del autofirmado). Para SANs en el autofirmado se requiere OpenSSL ≥ 1.1.1.
