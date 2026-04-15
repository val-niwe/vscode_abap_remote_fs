import { RemoteManager, createClient } from "../config"
import { AFsService, Root } from "abapfs"
import { Uri, FileSystemError, workspace } from "vscode"
import { ADTClient } from "abap-adt-api"
import { LogOutPendingDebuggers } from "./debugger"
import { SapSystemValidator } from "../services/sapSystemValidator"
import { LocalFsProvider } from "../fs/LocalFsProvider"
import { log } from "../lib"
import { clearSsoSession } from "../s4hanacloud"
export const ADTSCHEME = "adt"
export const ADTURIPATTERN = /\/sap\/bc\/adt\//

const roots = new Map<string, Root>()
const clients = new Map<string, ADTClient>()
const creations = new Map<string, Promise<void>>()

const missing = (connId: string) => {
  return FileSystemError.FileNotFound(`No ABAP server defined for ${connId}`)
}

export const abapUri = (u?: Uri) => u?.scheme === ADTSCHEME && !LocalFsProvider.useLocalStorage(u)

async function create(connId: string) {
  const manager = RemoteManager.get()
  const connection = await manager.byIdAsync(connId)
  if (!connection) throw Error(`Connection not found ${connId}`)

  // 🔐 VALIDATE SYSTEM ACCESS BEFORE CLIENT CREATION
  log(`🔍 Validating SAP system access for connection: ${connId}`)
  const validator = SapSystemValidator.getInstance()
  await validator.validateSystemAccess(
    connection.url,
    connection.sapGui?.server,
    connection.username
  )
  log(`✅ SAP system validation passed for: ${connId}`)

  let client
  if (connection.s4HanaCloud) {
    // S/4HANA Cloud: uses browser-based SSO via re-entrance ticket.
    // The BearerFetcher returns the ticket, ADTClient sets
    // "Authorization: bearer <ticket>" on each request.  We intercept that
    // and replace it with "MYSAPSSO2: <ticket>" which S/4HANA Cloud requires.
    log(`☁️ Connecting to S/4HANA Cloud system: ${connId}`)
    client = createClient(connection)
    addS4HanaCloudAuthInterceptor(client)
    addS4HanaCloudAuthInterceptor(client.statelessClone)
    try {
      await client.login()
      await client.statelessClone.login()
    } catch (loginError) {
      // If SSO session expired, clear it and retry
      clearSsoSession(connId)
      client = createClient(connection)
      addS4HanaCloudAuthInterceptor(client)
      addS4HanaCloudAuthInterceptor(client.statelessClone)
      await client.login()
      await client.statelessClone.login()
    }

    // Fix LIKE issue: Add Content-Type header for SQL queries
    addContentTypeInterceptor(client)
    addContentTypeInterceptor(client.statelessClone)
  } else if (connection.oauth || connection.password) {
    client = createClient(connection)
    await client.login() // raise exception for login issues
    await client.statelessClone.login()

    // Fix LIKE issue: Add Content-Type header for SQL queries
    addContentTypeInterceptor(client)
    addContentTypeInterceptor(client.statelessClone)
  } else {
    const password = (await manager.askPassword(connection.name)) || ""
    if (!password) throw Error("Can't connect without a password")
    client = await createClient({ ...connection, password })
    await client.login() // raise exception for login issues
    await client.statelessClone.login()
    connection.password = password
    const { name, username } = connection
    await manager.savePassword(name, username, password)

    // Fix LIKE issue: Add Content-Type header for SQL queries
    addContentTypeInterceptor(client)
    addContentTypeInterceptor(client.statelessClone)
  }

  // @ts-ignore
  const service = new AFsService(client)
  const newRoot = new Root(connId, service)
  roots.set(connId, newRoot)
  clients.set(connId, client)
}

/**
 * Add Content-Type header interceptor for SQL datapreview requests (LIKE issue fix)
 */
function addContentTypeInterceptor(adtClient: ADTClient) {
  try {
    const httpClient = adtClient.httpClient as any
    if (
      httpClient &&
      typeof httpClient === "object" &&
      httpClient.httpclient &&
      typeof httpClient.httpclient === "object" &&
      httpClient.httpclient.axios &&
      typeof httpClient.httpclient.axios.interceptors === "object"
    ) {
      httpClient.httpclient.axios.interceptors.request.use((config: any) => {
        if (!config || typeof config !== "object") {
          return config
        }
        if (typeof config.url === "string" && config.url.includes("/datapreview/freestyle")) {
          config.headers = config.headers || {}
          config.headers["Content-Type"] = "text/plain"
        }
        return config
      })
    }
  } catch (error) {
    log(`⚠️ Failed to add Content-Type interceptor: ${error}`)
  }
}

/**
 * Add axios request/response interceptors that implement the correct
 * S/4HANA Public Cloud authentication handshake using reentrance tickets.
 *
 * Lifecycle:
 *  1. First request (session establishment — the ADT login call):
 *     ADTClient sets "Authorization: bearer <ticket>"; we convert it to
 *     "MYSAPSSO2: <ticket>" + "x-sap-security-session: create".
 *     The server creates an ABAP session and returns a session cookie + CSRF token.
 *
 *  2. All subsequent requests:
 *     ADTClient still adds "Authorization: bearer <ticket>" (same ticket kept
 *     in the private `bearer` field).  We convert it to "MYSAPSSO2: <ticket>"
 *     for authentication, but omit "x-sap-security-session: create" to avoid
 *     re-creating the ABAP session on every call (which would cause the server
 *     to return a session-establishment response instead of the requested data).
 *     Note: axios in Node.js does not forward session cookies automatically,
 *     so MYSAPSSO2 must be sent on every request to authenticate.
 *
 *  3. Session expiry / re-login:
 *     When the server returns 401, the library's auto-login kicks in and calls
 *     `login()` again, obtaining a fresh ticket.  Our response error interceptor
 *     resets `sessionEstablished` so that the re-login request re-sends the
 *     "x-sap-security-session: create" header to establish a new ABAP session.
 */
function addS4HanaCloudAuthInterceptor(adtClient: ADTClient) {
  try {
    const httpClient = adtClient.httpClient as any
    if (
      httpClient &&
      typeof httpClient === "object" &&
      httpClient.httpclient &&
      typeof httpClient.httpclient === "object" &&
      httpClient.httpclient.axios &&
      typeof httpClient.httpclient.axios.interceptors === "object"
    ) {
      const axios = httpClient.httpclient.axios
      // Per-client flag: true once the first MYSAPSSO2 login succeeded.
      // Used only to suppress "x-sap-security-session: create" on subsequent requests.
      let sessionEstablished = false

      axios.interceptors.request.use((config: any) => {
        if (!config || typeof config !== "object") return config
        const headers = config.headers || {}
        const auth: unknown = headers.Authorization || headers.authorization
        if (typeof auth === "string" && auth.toLowerCase().startsWith("bearer ")) {
          const ticket = auth.substring(7)
          delete headers.Authorization
          delete headers.authorization
          // Always send MYSAPSSO2 — axios (Node.js) does not forward session cookies,
          // so the ticket must be present on every request for authentication.
          headers.MYSAPSSO2 = ticket
          if (!sessionEstablished) {
            // First request only: tell the server to create a new ABAP session.
            // Sending this header on subsequent requests causes the server to
            // return a session-creation confirmation instead of the requested data.
            headers["x-sap-security-session"] = "create"
          }
          config.headers = headers
        }
        return config
      })

      // Mark session as established after the first successful response, and
      // reset it when a 401 is received so the next login attempt re-sends
      // "x-sap-security-session: create" to establish a fresh ABAP session.
      axios.interceptors.response.use(
        (response: any) => {
          sessionEstablished = true
          return response
        },
        (error: any) => {
          if (error?.response?.status === 401) {
            sessionEstablished = false
          }
          return Promise.reject(error)
        }
      )
    }
  } catch (error) {
    log(`⚠️ Failed to add S/4HANA Cloud auth interceptor: ${error}`)
  }
}

function createIfMissing(connId: string) {
  if (roots.get(connId)) return
  let creation = creations.get(connId)
  if (!creation) {
    creation = create(connId)
    creations.set(connId, creation)
    creation.finally(() => creations.delete(connId))
  }
  return creation
}

export async function getOrCreateClient(connId: string, clone = true) {
  if (!clients.has(connId)) {
    try {
      await createIfMissing(connId)
    } catch (error) {
      // Re-throw validation errors with original message instead of generic "missing" error
      throw error // Preserve the original validation error message
    }
  }
  return getClient(connId, clone)
}

export function getClient(connId: string, clone = true) {
  const client = clients.get(connId)
  if (client) return clone ? client.statelessClone : client

  // If client doesn't exist, this means validation failed or connection was never established
  // Instead of generic "missing" error, provide more helpful feedback
  throw new Error(
    `SAP system '${connId}' is not accessible. This may be due to whitelist restrictions or connection issues. Check the extension logs for validation details.`
  )
}

export const getRoot = (connId: string) => {
  const root = roots.get(connId)
  if (root) return root
  throw missing(connId)
}

export const uriRoot = (uri: Uri) => {
  if (abapUri(uri)) return getRoot(uri.authority)
  throw missing(uri.toString())
}

export const getOrCreateRoot = async (connId: string) => {
  if (!roots.has(connId)) await createIfMissing(connId)
  return getRoot(connId)
}

export function hasLocks() {
  for (const root of roots.values()) if (root.lockManager.lockedPaths().next().value) return true
}
export async function disconnect() {
  const connected = [...clients.values()]
  const main = connected.map(c => c.logout())
  const clones = connected
    .map(c => c.statelessClone)
    .filter(c => c.loggedin)
    .map(c => c.logout())
  await Promise.all([...main, ...clones, ...LogOutPendingDebuggers()])
  return
}

export const rootIsConnected = (connId: string) =>
  !!workspace.workspaceFolders?.find(
    f => f.uri.scheme === ADTSCHEME && f.uri.authority === connId?.toLowerCase()
  )
