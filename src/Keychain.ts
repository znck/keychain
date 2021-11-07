import * as Path from 'path'
import * as Hex from 'encoding/hex'

const SECURITY = '/usr/bin/security'

export class Keychain {
  /**
   * Get available keychains.
   *
   * @param options Manipulate search results
   * @returns List of absolute paths of keychains
   */
  public static async getKeychains(options?: {
    /**
     * Use the specified preference domain
     */
    domain?: 'user' | 'system' | 'common' | 'dynamic'
    /**
     * Set the search list to the specified keychains
     */
    search: string[]
  }): Promise<string[]> {
    const output = await exec(
      SECURITY,
      'list-keychains',
      ...(isDefined(options?.domain) ? ['-d', options!.domain] : []),
      ...(isDefined(options?.search) ? ['-s', ...options!.search] : []),
    )

    return output
      .trim()
      .split(/\n/)
      .map((line) => line.trim().replace(/^"|"$/g, ''))
  }

  public static async create(
    fileName: string,
    password?: string,
  ): Promise<Keychain> {
    fileName = Path.resolve(fileName)

    await exec(
      SECURITY,
      'create-keychain',
      ...(isDefined(password) ? ['-p', password] : ['-P']),
      fileName,
    )

    return new Keychain(fileName)
  }

  public static async delete(fileName: string): Promise<void> {
    await exec(SECURITY, 'delete-keychain', Path.resolve(fileName))
  }

  public constructor(public readonly fileName: string) {}

  public async addGenericPassword(item: GenericPasswordItem): Promise<void> {
    await exec(
      SECURITY,
      'add-generic-password',
      ...['-a', item.account],
      ...['-s', item.service],
      ...(item.replace === true ? ['-U'] : []),
      ...(isDefined(item.type) ? ['-C', item.type] : []),
      ...(isDefined(item.kind) ? ['-D', item.kind] : []),
      ...(isDefined(item.comment) ? ['-j', item.comment] : []),
      ...(isDefined(item.label) ? ['-l', item.label] : []),
      ...(isDefined(item.applications)
        ? Array.isArray(item.applications)
          ? item.applications.flatMap((application) => ['-T', application])
          : item.applications
          ? ['-A', '']
          : ['-T', '']
        : []),
      ...['-w', item.password],
      this.fileName,
    )
  }

  public async deleteGenericPassword(
    item: Omit<GenericPasswordItem, 'password' | 'applications' | 'replace'>,
  ): Promise<void> {
    await exec(
      SECURITY,
      'delete-generic-password',
      ...['-a', item.account],
      ...['-s', item.service],
      ...(isDefined(item.type) ? ['-C', item.type] : []),
      ...(isDefined(item.kind) ? ['-D', item.kind] : []),
      ...(isDefined(item.comment) ? ['-j', item.comment] : []),
      ...(isDefined(item.label) ? ['-l', item.label] : []),
      this.fileName,
    )
  }

  public async getItems(): Promise<
    Omit<GenericPasswordItem, 'password' | 'applications' | 'replace'>[]
  > {
    const items: Array<
      Omit<GenericPasswordItem, 'password' | 'applications' | 'replace'>
    > = []
    const output = await exec(SECURITY, 'dump-keychain', this.fileName)

    const blocks: string[] = []
    let current = ''
    output.split('\n').forEach((line) => {
      if (line.startsWith('keychain: ')) {
        if (current !== '') {
          blocks.push(current)
          current = ''
        }
      }
      current += line + '\n'
    })
    if (current !== '') {
      blocks.push(current)
    }

    const find = (content: string, start: string, end: string): string => {
      const index = content.indexOf(start)
      if (index < 0) return ''
      const s = index + start.length
      const e = content.indexOf(end, s)
      if (index < 0) return ''

      return content.substring(s, e)
    }
    
    for (const block of blocks) {
      items.push({
        account: find(block, '    0x00000007 <blob>="', '"'),
        service: find(block, '    "svce"<blob>="', '"'),
      })
    }

    return items
  }

  public async findGenericPassword(
    item: Omit<GenericPasswordItem, 'password' | 'applications' | 'replace'>,
  ): Promise<string> {
    const password = await exec(
      SECURITY,
      'find-generic-password',
      ...['-a', item.account],
      ...['-s', item.service],
      ...(isDefined(item.type) ? ['-C', item.type] : []),
      ...(isDefined(item.kind) ? ['-D', item.kind] : []),
      ...(isDefined(item.comment) ? ['-j', item.comment] : []),
      ...(isDefined(item.label) ? ['-l', item.label] : []),
      '-w',
      this.fileName,
    )
    if (/^[a-f0-9]+$/i.test(password)) {
      const result = new TextDecoder().decode(
        Hex.decode(new TextEncoder().encode(password)),
      )

      if (result.includes('\n')) return result
    }

    return password
  }

  public async unlock(password?: string): Promise<void> {
    await exec(
      SECURITY,
      'unlock-keychain',
      ...(isDefined(password) ? ['-p', password] : '-u'),
      this.fileName,
    )
  }

  public async lock(): Promise<void> {
    await exec(SECURITY, 'lock-keychain', this.fileName)
  }

  public async dump(): Promise<void> {
    console.log(await exec(SECURITY, 'dump-keychain', '-adr', this.fileName))
  }
}

export interface GenericPasswordItem {
  account: string
  service: string
  password: string
  kind?: string
  label?: string
  type?: 'note'
  comment?: string
  applications?: string[] | boolean
  replace?: boolean
}

export class ProcessExeption extends Error {
  constructor(public readonly code: number, output: string) {
    super(output)
  }
}

export function isDefined<T>(value: T | undefined): value is T {
  return value !== undefined
}

async function exec(command: string, ...args: string[]): Promise<string> {
  const permission = await Deno.permissions.request({
    name: 'run',
    command,
  })

  // console.debug(
  //   command,
  //   ...args.map((arg) =>
  //     /[^a-z0-9-]/i.test(arg) || arg.trim().length === 0
  //       ? `'${arg.replace(/[']/g, "\\'")}'`
  //       : arg,
  //   ),
  // )

  if (permission.state !== 'granted') {
    throw new ProcessExeption(403, `Permission denied to execute ${command}`)
  }

  const process = await Deno.run({
    cmd: [command, ...args],
    stdout: 'piped',
    stderr: 'piped',
  })

  try {
    const decoder = new TextDecoder()
    const [status, error, output] = await Promise.all([
      process.status(),
      process.stderrOutput(),
      process.output(),
    ])

    if (!status.success) {
      throw new ProcessExeption(
        status.code,
        decoder.decode(error).replace(/\n$/, ''),
      )
    }

    return decoder.decode(output).replace(/\n$/, '')
  } finally {
    process.close()
  }
}
