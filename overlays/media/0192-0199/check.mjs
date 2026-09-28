// Executable specification examples; not a protocol/server/Script implementation.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'

const vectors = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'))
let passed = 0
function check(name, run) {
  try { run(); passed++ } catch (error) { throw new Error(name, { cause: error }) }
}
const u64 = value => typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) <= 18446744073709551615n
const wellFormed = value => value.isWellFormed()
function canonical(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'string') {
    assert(wellFormed(value), 'invalid Unicode')
    return JSON.stringify(value)
  }
  if (typeof value === 'number') {
    assert(Number.isSafeInteger(value), 'unsafe or noninteger number')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  assert(value && Object.getPrototypeOf(value) === Object.prototype, 'not a JSON object')
  return '{' + Object.keys(value).sort().map(key => canonical(key) + ':' + canonical(value[key])).join(',') + '}'
}
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const digest = (type, body) => hash(Buffer.concat([Buffer.from('BRC-OUTPUT/1/' + type), Buffer.from([0]), Buffer.from(canonical(body))]))

for (const v of vectors.canonical) check(v.name, () => {
  assert.equal(canonical(v.body), v.canonical)
  assert.equal(digest(v.type, v.body), v.digest)
})
for (const v of vectors.u64) check('u64 ' + JSON.stringify(v.value), () => assert.equal(u64(v.value), v.valid))
for (const value of [NaN, Infinity, 1.2, 9007199254740992, '\ud800']) {
  check('reject non-protocol JSON value', () => assert.throws(() => canonical(value)))
}
check('digest type domain separation', () => assert.notEqual(digest('a', {version:1}), digest('b', {version:1})))
check('critical extension processing', () => {
  const supported = new Set(['urn:example:known'])
  const accept = object => (object.critical ?? []).every(key => key in (object.extensions ?? {}) && supported.has(key))
  assert(accept({extensions:{'urn:example:future':1}}))
  assert(!accept({extensions:{'urn:example:future':1},critical:['urn:example:future']}))
  assert(!accept({critical:['urn:example:known']}))
})

check('source-specific membership and receipt deduplication', () => {
  const seen = new Map(), memberships = new Map()
  for (const event of vectors.membership.events) {
    const key = canonical([event.source,event.id]), bytes = canonical(event)
    if (seen.has(key)) { assert.equal(seen.get(key), bytes); continue }
    seen.set(key, bytes)
    const sources = memberships.get(event.outpoint) ?? new Set()
    if (event.kind === 'output') sources.add(event.source)
    else sources.delete(event.source)
    memberships.set(event.outpoint, sources)
  }
  assert.equal(seen.size, vectors.membership.receipts)
  assert.deepEqual([...memberships.get('x')].sort(), vectors.membership.remainingSources)
  assert.equal(vectors.membership.events.some(e => e.kind === 'spend'), vectors.membership.spent)
})
check('equivocation cannot overwrite receipt', () => {
  const original = canonical(vectors.membership.events[0])
  assert.notEqual(original, canonical({...vectors.membership.events[0],outpoint:'y'}))
})
check('bad proof does not poison output identity', () => {
  const variants = new Map([['bad','invalid'],['good','verified']])
  assert([...variants.values()].includes('verified'))
  assert.equal(variants.get('bad'),'invalid')
})
check('partition and chain are part of identity', () => {
  const key = (account, genesis) => canonical([account,genesis,'tx',0])
  assert.notEqual(key('a','main'), key('b','main'))
  assert.notEqual(key('a','main'), key('a','test'))
})
for (const v of vectors.cursor) check(v.name, () => {
  let members = new Set(v.snapshot), through = BigInt(v.watermark)
  const seen = new Set()
  for (const group of [...v.log, ...v.log]) {
    if (seen.has(group.id)) continue
    assert(BigInt(group.sequence) > through)
    const next = new Set(members)
    group.remove.forEach(x => next.delete(x))
    group.add.forEach(x => next.add(x))
    // The public revision becomes visible only after this whole group commits.
    members = next; through = BigInt(group.sequence); seen.add(group.id)
  }
  assert.deepEqual([...members].sort(), v.expected)
  assert.equal(String(through), v.through)
})
check('checkpoint follows durable commit', () => {
  let checkpoint = '10', pending = null
  const receive = () => { pending = {cursor:'11',observations:['replacement']} }
  receive()
  assert.equal(checkpoint,'10')
  pending = null // crash before commit
  assert.equal(checkpoint,'10')
  receive()
  const durable = structuredClone(pending)
  checkpoint = durable.cursor
  assert.deepEqual(durable.observations,['replacement'])
  assert.equal(checkpoint,'11')
})
check('expiry is exclusive and reset explicit', () => {
  const status = (now, expiry, epochMatches) => now >= expiry || !epochMatches ? 'reset-required' : 'resume'
  assert.equal(status(99n,100n,true),'resume')
  assert.equal(status(100n,100n,true),'reset-required')
  assert.equal(status(99n,100n,false),'reset-required')
})
check('stale verification cannot publish in a new context', () => {
  const complete = (job, current) => job.context === current ? 'verified' : 'context-changed'
  assert.equal(complete({context:'tip-a'},'tip-b'),'context-changed')
})
for (const v of vectors.capability) check(v.name, () => assert.equal(v.available.includes(v.required), v.valid))
for (const v of vectors.proposal) check('proposal ' + canonical(v.incoming), () => {
  const {head:h,incoming:n} = v
  const result = h?.id === n.id ? 'replay' :
    (!h ? n.revision === '0' && n.previous === null : n.previous === h.id && BigInt(n.revision) === BigInt(h.revision)+1n) ? 'recorded' : 'conflict'
  assert.equal(result,v.expected)
})

const moneyMax = 2100000000000000n
for (const v of vectors.purchase) check(v.name, () => {
  const old = BigInt(v.old), price = BigInt(v.price), next = BigInt(v.next)
  const valid = old > 0n && price > 0n && next <= moneyMax && next === old+price && v.sameScript && v.receipt && v.lineage
  assert.equal(valid,v.valid)
})
for (const v of vectors.administration) check(v.name, () => {
  const inputs=v.inputs.map(BigInt), outputs=v.outputs.map(BigInt), payout=BigInt(v.payout), reserve=BigInt(v.reserve)
  const sum = xs => xs.reduce((a,b)=>a+b,0n)
  const shape = {
    split: inputs.length===1 && outputs.length>=2 && outputs.length<=64 && payout===0n,
    merge: inputs.length>=2 && inputs.length<=64 && outputs.length===1 && payout===0n,
    payout: inputs.length===1 && outputs.length===1 && payout>0n,
    retire: inputs.length===1 && outputs.length===0 && payout===sum(inputs)
  }[v.route]
  const valid = v.authorized && v.unique && v.lineage && shape &&
    outputs.every(x=>x>=reserve && x<=moneyMax) && sum(inputs)===sum(outputs)+payout
  assert.equal(valid,v.valid)
})
check('purchase receipt exact bytes and minimal push', () => {
  const v = vectors.receipt
  const payload=Buffer.concat([Buffer.from(v.magic),Buffer.from([1,1]),...['listingId','acquisitionId','requestDigest','recipient','termsDigest'].map(key=>Buffer.from(v[key],'hex'))])
  assert.equal(payload.length,v.purchaseBytes)
  assert.equal(payload.subarray(70,102).toString('hex'),v.requestDigest)
  assert.equal(payload.subarray(102,135).toString('hex'),v.recipient)
  assert.equal(payload.subarray(135).toString('hex'),v.termsDigest)
  const script=Buffer.concat([Buffer.from([0,0x6a,0x4c,payload.length]),payload])
  assert.equal(script.length,171)
  assert.equal(script.subarray(0,4).toString('hex'),'006a4ca7')
})
check('admin receipt exact bytes', () => {
  const counters=Buffer.alloc(16)
  counters.writeUInt32LE(2,0); counters.writeUInt32LE(1,4); counters.writeBigUInt64LE(0n,8)
  const payload=Buffer.concat([Buffer.from('ROSL'),Buffer.from([1,3]),Buffer.from(vectors.receipt.listingId,'hex'),counters,Buffer.alloc(32)])
  assert.equal(payload.length,vectors.receipt.adminBytes)
  assert.equal(payload.readUInt32LE(38),2)
  assert.equal(payload.readUInt32LE(42),1)
})
check('funding retry and lost reply preserve one acquisition', () => {
  const v = vectors.acquisition, payments=new Map()
  let charges=0, accruals=0, delivered
  for (const action of v.actions) {
    if (action==='fund' && !payments.has(v.payment)) {payments.set(v.payment,v.request);charges++;accruals++}
    if (action==='recover' && payments.get(v.payment)===v.request) delivered='same-capability'
  }
  assert.equal(charges,v.expectedCharges); assert.equal(accruals,v.expectedAccruals)
  assert.equal(delivered,v.expectedDelivery)
  assert.notEqual(payments.get(v.payment),'another-request')
})
check('recipient authorization independent of public transaction', () => {
  const recover = caller => caller === vectors.acquisition.buyer ? 'same-capability' : 'not-found'
  assert.equal(recover('buyer-b'),'not-found')
  assert.equal(recover('buyer-a'),'same-capability')
})
check('covenant acquisition cannot change accepted txid', () => {
  const accepted='transaction-a'
  const bind = txid => txid===accepted ? 'replay' : 'conflict'
  assert.equal(bind('transaction-a'),'replay'); assert.equal(bind('transaction-b'),'conflict')
})
check('LCH request ID is not outer request digest', () => {
  const requestId='11'.repeat(32)
  assert.notEqual(digest('purchase-request',{requestId}),requestId)
})
check('LCH offer uses an existing anchor before descriptor hashes offer', () => {
  const binding={lineageAnchor:{txid:'11'.repeat(32),outputIndex:0}}
  assert(!('listingId' in binding)); assert(!('genesis' in binding))
})
for (const v of vectors.eviction) check(v.name, () => {
  const decisions=new Set()
  for (const [action,id] of v.actions) action==='suppress' ? decisions.add(id) : decisions.delete(id)
  assert.deepEqual([...decisions].sort(),v.remaining)
})
check('independent roots can disagree', () => {
  const roots={a:new Set(['outpoint']),b:new Set()}
  assert(roots.a.has('outpoint')); assert(!roots.b.has('outpoint'))
})
check('restoration requires currentness and absence of other blocks', () => {
  const restore=(unspent,blocks)=>unspent && blocks.size===0
  assert(!restore(false,new Set()));assert(!restore(true,new Set(['other'])));assert(restore(true,new Set()))
})
console.log(JSON.stringify({passed,scope:'representation and specification models; no Script, crypto, database or HTTP certification'}))
