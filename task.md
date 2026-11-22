# Tarea

# Descripción de la Tarea

Se debe diseñar y construir un sistema pequeño que permita a un usuario guardar una clave secreta de Nostr y usarla mediante NIP-46 para autenticarse en Stacker News.

Algunas partes del producto y de la implementación se dejaron sin especificar intencionalmente. Cuando algo no esté claro, se puede:

- Hacer supuestos razonables y documentarlos, o
- Hacer preguntas aclaratorias.


No se espera una billetera lista para producción, una extensión de navegador ni un firmante universal.

# Expectativas Mínimas

La entrega debe incluir, como mínimo:

- Una forma para que el usuario ingrese o cree una clave secreta de Nostr.
- Una forma de que esa clave sea usada por un firmante NIP-46 implementado por la persona postulante.
- Una demostración del flujo de inicio de sesión en Stacker News funcionando de principio a fin.

### Entrega

Se debe enviar el link del repositorio de código (repositorio público), que incluya:

- Implementación de la solución
- Un README breve con instrucciones de instalación, supuestos y tradeoffs.
- Los registros de conversación con el agente de IA.

## Referencias

- Nostr: https://nostr.com
- NIP-46: https://github.com/nostr-protocol/nips/blob/master/46.md
- Inicio de sesión con Nostr en Stacker News: https://stacker.news/signup?callbackUrl=https%3A%2F%2Fstacker.news%2F&type=nostr