[English](README.md) · **Español**

# kazna

Un pequeño guardián de claves Nostr y **firmante remoto NIP-46** en Python, hecho para
iniciar sesión en [Stacker News](https://stacker.news) sin entregarle tu clave secreta al sitio.

Creas (o importas) una identidad Nostr, ejecutas `kazna bunker <nombre>` y pegas en Stacker
News el enlace `bunker://` que imprime. El sitio le pide a kazna, a través de relays Nostr, que
firme su desafío de inicio de sesión; kazna te muestra la solicitud y solo firma si la apruebas.

## Demo

https://github.com/user-attachments/assets/66412f93-1f4a-44ce-80fc-e57e506ea856

## Instalación

Requiere Docker con Compose. Todo se ejecuta en contenedores.

```sh
docker compose build
alias kazna='docker compose run --rm kazna'      # bash/zsh
alias kazna 'docker compose run --rm kazna'      # fish
```

Usa el alias desde el directorio del proyecto, donde está `docker-compose.yml`.

## Iniciar sesión en Stacker News

```sh
kazna create vavilov        # o: kazna import vavilov  (pega un nsec1… o la clave en hex)
kazna bunker vavilov
```

`bunker` imprime un enlace de un solo uso y queda esperando:

```
signing as  vavilov  npub1…
signer key  65ec0cb4…  (new for this session)

paste this link into the app; it works for one connection:

bunker://65ec0cb4…?relay=wss%3A%2F%2Fnos.lol&relay=wss%3A%2F%2Frelay.primal.net&secret=3685…
```

1. Abre <https://stacker.news/signup?callbackUrl=https%3A%2F%2Fstacker.news%2F&type=nostr>.
2. Elige la opción de token / NIP-05, pega el enlace `bunker://` y envíalo.
3. kazna muestra el evento que Stacker News quiere firmar:

   ```
   client 04092e30…7e2f asks to sign:
     kind     27235
     content  'Stacker News Authentication'
     tag      challenge a3ff237b…
     tag      u https://stacker.news
     tag      method GET
   sign it? [y/N]
   ```

4. Responde `y`. Stacker News verifica la firma e inicia tu sesión. Una pubkey nueva obtiene
   una cuenta nueva, que Stacker News solo crea desde la página `/signup`.

Cada enlace sirve para una sola conexión. Cuando un cliente se conecta, kazna imprime un enlace
nuevo para el siguiente inicio de sesión.

## Otros comandos

```sh
kazna show vavilov                         # npub, pubkey en hex y un enlace al perfil
kazna post vavilov -m "marri marri mapu"   # firma y publica una nota de texto (kind 1)
```

`post` muestra la respuesta de cada relay y un enlace de njump.me a la nota. Las notas en relays
públicos son públicas y prácticamente permanentes.

## Cómo funciona

```
Página de Stacker News (NDK, en tu navegador)   relays             kazna bunker
  connect [ "", secret ]          ── kind 24133, cifrado ──►   valida el secreto de un uso → "ack"
  get_public_key                  ─────────────────────────►   pubkey de tu identidad
  sign_event {kind 27235, challenge}  ─────────────────────►   pregunta y/N → firma con tu clave
  ◄──────────────────────── evento firmado ──────────────────
  → el servidor de Stacker News verifica id, firma Schnorr y challenge → sesión
```

- **Dos claves.** Tu clave de identidad (guardada en disco) solo firma los eventos que apruebas.
  Cada sesión de `bunker` crea una *clave de firmante* aparte; el cliente se comunica con esa y
  conoce tu identidad mediante `get_public_key`, como describe NIP-46.
- **Cifrado.** Las solicitudes se descifran con NIP-44 o NIP-04, detectado en cada mensaje, y la
  respuesta usa el mismo esquema. El cliente de Stacker News (NDK 2.12.2) usa NIP-04 por defecto.
- **Métodos.** `connect`, `get_public_key`, `sign_event`, `ping` y `logout`. Cualquier otro
  recibe el error `unsupported method`. Se rechazan las solicitudes de clientes no conectados.
- **Se verifican los sobres.** Los eventos entrantes con id o firma inválidos se descartan. Los
  relays se reconectan con espera creciente, y un evento recibido por varios relays se procesa
  una sola vez.

## Almacenamiento

Cada identidad es un directorio `identities/<nombre>/` con `key.json` (name, pubkey, npub,
nsec, created_at), con permisos `0600` dentro de un directorio `0700`. `identities/` se monta en
`/data` (`KAZNA_HOME`) y git lo ignora.

## Pruebas

```sh
docker compose run --rm --entrypoint pytest kazna
```

Las pruebas unitarias incluyen los vectores de prueba oficiales de NIP-44, los ejemplos de
NIP-19, NIP-04 contrastado con OpenSSL y las reglas del protocolo del firmante.

El inicio de sesión se prueba contra **el propio código cliente de Stacker News**:
`tests/sn-client/login.mjs` reproduce su login (mismo NDK 2.12.2, mismo parche de URL, mismo
evento kind 27235) y luego aplica las verificaciones que hace su servidor. Corre contra un relay
local:

```sh
docker compose --profile dev up -d relay
kazna bunker vavilov --relay ws://relay:8080          # en una terminal
docker compose --profile dev run --rm sn-client "<bunker://…>" [--nip44]
docker compose --profile dev down
```

## Supuestos y tradeoffs

- **Stacker News es el cliente objetivo.** Donde su cliente (NDK 2.12.2) difiere del texto
  actual de NIP-46, kazna acepta ambas formas. Acepta un primer parámetro vacío en `connect` y
  responde `"ack"` en lugar de devolver el secreto.
- **Solo el flujo `bunker://`.** Stacker News no ofrece `nostrconnect://`, así que no está
  implementado. Tampoco los desafíos `auth_url` ni `switch_relays`.
- **Sin métodos de cifrado/descifrado.** `nip04_*` y `nip44_*` permitirían a un cliente
  conectado leer tus mensajes directos, y el login no los necesita, así que se rechazan.
- **Las sesiones viven en memoria.** La clave de firmante y los clientes conectados se pierden
  cuando `bunker` se detiene. Stacker News crea una clave de cliente nueva en cada login de todos
  modos.
- **Una pregunta sí/no en lugar de políticas de permisos.** `--yes` aprueba todo
  automáticamente, solo para pruebas automatizadas.
- **La clave secreta se guarda en texto plano**, protegida solo por los permisos del archivo.
  El cifrado con contraseña (NIP-49) está planificado.
- **Relays por defecto:** `nos.lol` y `relay.primal.net`, los que funcionaron en las pruebas.
  Usa `--relay` para elegir otros; la página de Stacker News se conecta a los que indique el
  enlace.
- **Librerías de bajo nivel en lugar de un SDK de Nostr.** Los eventos, NIP-19, NIP-04, NIP-44 y
  NIP-46 están implementados aquí sobre `coincurve`, `cryptography`, `bech32` y `websockets`.

## Estructura

```
kazna/
  identity.py  Identity (par de claves, ECDH) e IdentityStore (un directorio por identidad)
  event.py     Event: serialización NIP-01, id, firma, verificación, parseo de JSON no confiable
  nip19.py     codificaciones bech32: npub, nsec, nevent
  cipher.py    clase base Cipher
  nip04.py     Nip04Cipher (AES-256-CBC)
  nip44.py     Nip44Cipher (v2: ChaCha20 + HMAC-SHA256)
  relay.py     RelayConnection (websocket con reconexión) y RelayPool
  nip46.py     RemoteSigner (métodos) y Bunker (transporte por relays), BunkerUrl
  approval.py  PromptApprover (y/N en la terminal) y AutoApprover
  cli.py       comandos argparse
tests/
  test_*.py    pruebas unitarias; vectors/ contiene los vectores de NIP-44
  sn-client/   cliente de login de Stacker News (Node, NDK 2.12.2) para pruebas de punta a punta locales
```
