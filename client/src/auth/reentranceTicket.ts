import http from "node:http"
import open from "open"
import { ADTClient } from "abap-adt-api"
import { log } from "../lib"

const DEFAULT_TIMEOUT = 60 * 1000
const ADT_REENTRANCE_ENDPOINT = "/sap/bc/sec/reentrance"
const REDIRECT_PATH = "/redirect"
const FETCH_CSRF_TOKEN = "fetch"
const SESSION_COOKIE_MARKER = "SAP_SESSIONID"

interface VirtualHostPayload {
  relatedUrls?: {
    API?: string
    UI?: string
  }
}

interface ReentranceBackend {
  apiHostname: string
  uiHostname: string
  logoffUrl: string
}

const parseStatus = (error: unknown): number | undefined => {
  const e = error as any
  return e?.status ?? e?.err ?? e?.response?.status
}

const isUnauthorized = (error: unknown): boolean => {
  const status = parseStatus(error)
  if (status === 401) {
    return true
  }
  return `${error}`.includes("401")
}

const hasSessionCookie = (h: any) => `${h.ascookies?.() || ""}`.includes(SESSION_COOKIE_MARKER)

const updateBaseUrl = (h: any, baseURL: string) => {
  h.baseURL = baseURL
  if (h.httpclient) {
    h.httpclient.baseURL = baseURL
    if (h.httpclient.axios?.defaults) {
      h.httpclient.axios.defaults.baseURL = baseURL
    }
  }
}

export function syncReentranceSession(sourceClient: ADTClient, targetClient: ADTClient) {
  const source = (sourceClient.httpClient as any) || {}
  const target = (targetClient.httpClient as any) || {}

  updateBaseUrl(target, source.baseURL)
  target.cookie = new Map(source.cookie || [])
  target.csrfToken = source.csrfToken
  target.__reentranceSessionEstablished = source.__reentranceSessionEstablished
}

async function readVirtualHosts(h: any, backendUrl: string): Promise<ReentranceBackend> {
  const origin = new URL(backendUrl).origin
  const response = await h.httpclient.axios.request({
    method: "GET",
    url: `${origin}/sap/public/bc/icf/virtualhost`,
    headers: {
      Accept: "application/json"
    }
  })

  if (response.status !== 200) {
    throw new Error(
      `Failed to fetch virtual hosts: ${response.status} ${response.statusText || ""}`
    )
  }

  const parsed =
    typeof response.data === "string"
      ? (JSON.parse(response.data || "{}") as VirtualHostPayload)
      : ((response.data || {}) as VirtualHostPayload)
  const ui = parsed.relatedUrls?.UI
  const api = parsed.relatedUrls?.API

  if (!ui || !api) {
    throw new Error("Invalid virtual host response: missing relatedUrls.UI or relatedUrls.API")
  }

  return {
    uiHostname: new URL(ui).origin,
    apiHostname: new URL(api).origin,
    logoffUrl: `${new URL(ui).origin}/sap/public/bc/icf/logoff`
  }
}

function getReentranceTicket(
  backend: ReentranceBackend,
  timeout = DEFAULT_TIMEOUT
): Promise<string> {
  return new Promise((resolve, reject) => {
    let resolved = false
    const server = http.createServer((req, res) => {
      const reqUrl = new URL(req.url || "/", `http://${req.headers.host}`)
      if (reqUrl.pathname !== REDIRECT_PATH) {
        return
      }

      const ticket = reqUrl.searchParams.get("reentrance-ticket")?.toString()
      if (ticket) {
        resolved = true
        res.writeHead(200, { "Content-Type": "text/html" })
        res.end(
          `<html><body><h3>Authentication successful</h3><p>You can close this tab.</p><script>window.close()</script></body></html>`
        )
        server.close()
        resolve(ticket)
      } else {
        resolved = true
        res.writeHead(500, { "Content-Type": "text/html" })
        res.end("<html><body><h3>Authentication failed</h3></body></html>")
        server.close()
        reject(new Error("Error getting reentrance ticket"))
      }
    })

    server.listen(0, async () => {
      try {
        const address = server.address()
        const port = typeof address === "object" && address ? address.port : undefined
        if (!port) {
          throw new Error("Unable to open local redirect server")
        }

        const scenario = process.env.FIORI_TOOLS_SCENARIO ?? "FTO1"
        const endpoint = process.env.FIORI_TOOLS_REENTRANCE_ENDPOINT ?? ADT_REENTRANCE_ENDPOINT
        const redirectUrl = `http://localhost:${port}${REDIRECT_PATH}`
        const loginUrl = `${backend.uiHostname}${endpoint}?scenario=${scenario}&redirect-url=${redirectUrl}`

        await open(loginUrl)
      } catch (error) {
        if (!resolved) {
          resolved = true
          server.close()
          reject(error)
        }
      }
    })

    setTimeout(() => {
      if (!resolved) {
        resolved = true
        server.close()
        reject(new Error(`Timeout. Did not get a response within ${timeout} ms`))
      }
    }, timeout)
  })
}

export function attachReentranceTicketLogin(client: ADTClient) {
  const h = (client.httpClient as any) || {}
  if (h.__reentranceTicketPatched) {
    return
  }

  Object.defineProperty(h, "loggedin", {
    configurable: true,
    get() {
      return !!this.__reentranceSessionEstablished || this.csrfToken !== FETCH_CSRF_TOKEN
    }
  })

  h.__reentranceTicketPatched = true

  h.login = async function reentranceLogin(forceFreshTicket = false) {
    if (this.loginPromise) {
      return this.loginPromise
    }

    if (!forceFreshTicket && this.__reentranceSessionEstablished && hasSessionCookie(this)) {
      return
    }

    this.auth = undefined
    this.bearer = undefined

    const qs: Record<string, string> = {}
    if (this.client) qs["sap-client"] = this.client
    if (this.language) qs["sap-language"] = this.language
    this.csrfToken = FETCH_CSRF_TOKEN

    const runLogin = async (forceNewTicket: boolean) => {
      const headers: Record<string, string> = {}
      const hasExistingSession = !forceNewTicket && hasSessionCookie(this)

      if (!hasExistingSession) {
        this.cookie.clear()
        this.__reentranceSessionEstablished = false
        const backend = await readVirtualHosts(this, this.baseURL)
        const reentranceTicket = await getReentranceTicket(backend)
        updateBaseUrl(this, backend.apiHostname)
        headers.MYSAPSSO2 = reentranceTicket
        headers["x-sap-security-session"] = "create"
      }

      const response = await this._request("/sap/bc/adt/compatibility/graph", {
        qs,
        headers
      })

      if (!hasSessionCookie(this)) {
        throw new Error("S/4HANA Cloud SSO login did not return an SAP session cookie")
      }

      this.__reentranceSessionEstablished = true

      if (this.csrfToken === FETCH_CSRF_TOKEN) {
        await this._request("/sap/bc/adt/compatibility/graph", { qs })
      }

      return response
    }

    try {
      this.loginPromise = runLogin(forceFreshTicket).catch(async (error: unknown) => {
        if (!forceFreshTicket && isUnauthorized(error)) {
          this.cookie.clear()
          this.bearer = undefined
          this.__reentranceSessionEstablished = false
          return runLogin(true)
        }
        throw error
      })
      await this.loginPromise
    } catch (error) {
      log(`S/4HANA Cloud SSO login failed: ${error}`)
      throw error
    } finally {
      this.loginPromise = undefined
    }
  }
}
