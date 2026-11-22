// Reproduces Stacker News's NIP-46 login with the same NDK version (2.12.2):
//   client side  components/nostr-auth.js + lib/nostr.js (URL patch, kind 27235 challenge event)
//   server side  the checks in pages/api/auth/[...nextauth].js (event id, schnorr sig, challenge tag)
//
// usage: node login.mjs <bunker://…> [--nip44]
import { createHash, randomBytes } from 'node:crypto'
import NDK, { NDKEvent, NDKNip46Signer } from '@nostr-dev-kit/ndk'
import { schnorr } from '@noble/curves/secp256k1'

class NDKNip46SignerURLPatch extends NDKNip46Signer {
  connectionTokenInit (connectionToken) {
    connectionToken = connectionToken.replace('bunker://', 'http://')
    return super.connectionTokenInit(connectionToken)
  }
}

const fail = (message) => { console.error(`FAIL: ${message}`); process.exit(1) }
const check = (condition, message) => { if (!condition) fail(message) }

const [token, ...flags] = process.argv.slice(2)
check(token?.startsWith('bunker://'), 'usage: node login.mjs <bunker://…> [--nip44]')
setTimeout(() => fail('timed out after 60s'), 60_000).unref()

const ndk = new NDK({ autoConnectUserRelays: false, autoFetchUserMutelist: false, clientName: 'stacker.news' })
const signer = new NDKNip46SignerURLPatch(ndk, token)
if (flags.includes('--nip44')) signer.rpc.encryptionType = 'nip44'
signer.once('authUrl', (url) => fail(`unexpected auth_url challenge: ${url}`))

const user = await signer.blockUntilReady()
console.log(`connected, user pubkey ${user.pubkey}`)

const k1 = randomBytes(32).toString('hex')
const event = new NDKEvent(ndk, {
  kind: 27235,
  created_at: Math.floor(Date.now() / 1000),
  tags: [['challenge', k1], ['u', 'https://stacker.news'], ['method', 'GET']],
  content: 'Stacker News Authentication'
})
await event.sign(signer)

const e = JSON.parse(JSON.stringify(event.rawEvent()))
const id = createHash('sha256').update(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])).digest('hex')
check(id === e.id, 'invalid event id')
check(schnorr.verify(e.sig, e.id, e.pubkey), 'invalid signature')
check(e.tags[0].length === 2 && e.tags[0][0] === 'challenge' && e.tags[0][1] === k1, 'challenge tag mismatch')
check(e.pubkey === user.pubkey, 'event pubkey differs from get_public_key')

console.log(`PASS: signed kind ${e.kind} event ${e.id} accepted by Stacker News's server checks (${signer.rpc.encryptionType})`)
process.exit(0)
