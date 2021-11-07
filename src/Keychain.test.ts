import { Keychain } from './Keychain.ts'
import { assert, assertEquals, assertThrowsAsync } from 'testing'
import * as FS from 'fs'

Deno.test('keychain search', async () => {
  const keychains = await Keychain.getKeychains()

  assert(keychains.length > 0, 'no keychains found')
})

Deno.test('keychain creation/deletion', async () => {
  const keychain = await Keychain.create(
    Date.now() + '.keychain-db',
    'password',
  )
  assert(await FS.exists(keychain.fileName))

  await Keychain.delete(keychain.fileName)
  assert(!(await FS.exists(keychain.fileName)))
})

Deno.test('generic password storage/retrival', async () => {
  const keychain = await Keychain.create(
    Date.now() + '.keychain-db',
    'password',
  )

  await keychain.addGenericPassword({
    account: 'My Note',
    service: 'My Note',
    password: 'A test note',
    applications: ['/usr/bin/security'],
    type: 'note',
    kind: 'secret note',
    comment: 'This is a secret note!',
  })

  assertEquals(
    await keychain.findGenericPassword({
      account: 'My Note',
      service: 'My Note',
    }),
    'A test note',
  )

  await keychain.deleteGenericPassword({
    account: 'My Note',
    service: 'My Note',
  })

  await assertThrowsAsync(async () => {
    await keychain.findGenericPassword({
      account: 'My Note',
      service: 'My Note',
    })
  })

  await Keychain.delete(keychain.fileName)
})

Deno.test('replace password', async () => {
  const keychain = await Keychain.create(
    Date.now() + '.keychain-db',
    'password',
  )

  await keychain.addGenericPassword({
    account: 'My Note',
    service: 'My Note',
    password: 'A test note',
    applications: ['/usr/bin/security'],
    type: 'note',
    kind: 'secret note',
    comment: 'This is a secret note!',
  })

  assertEquals(
    await keychain.findGenericPassword({
      account: 'My Note',
      service: 'My Note',
    }),
    'A test note',
  )

  await assertThrowsAsync(async () => {
    await keychain.addGenericPassword({
      account: 'My Note',
      service: 'My Note',
      password: 'A test note 2',
      applications: ['/usr/bin/security'],
      type: 'note',
      kind: 'secret note',
      comment: 'This is a secret note!',
    })
  })

  await keychain.addGenericPassword({
    account: 'My Note',
    service: 'My Note',
    password: 'A test note 3',
    applications: ['/usr/bin/security'],
    type: 'note',
    kind: 'secret note',
    comment: 'This is a secret note!',
    replace: true,
  })

  assertEquals(
    await keychain.findGenericPassword({
      account: 'My Note',
      service: 'My Note',
    }),
    'A test note 3',
  )

  await Keychain.delete(keychain.fileName)
})
