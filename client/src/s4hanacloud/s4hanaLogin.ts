/**
 * S/4HANA Cloud SSO Login
 *
 * Implements browser-based SSO authentication for S/4HANA Public Cloud systems
 * using a re-entrance ticket mechanism analogous to SAP ADT in Eclipse.
 *
 * Flow:
 * 1. Discover UI hostname via /sap/public/bc/icf/virtualhost
 * 2. Start a local HTTP server to handle the redirect callback
 * 3. Open the re-entrance endpoint in the user's browser:
 *    ${uiHostname}/sap/bc/sec/reentrance?scenario=FTO1&redirect-url=http://localhost:{port}/redirect
 * 4. User authenticates via IDP
 * 5. S/4HANA redirects back to the local server with the reentrance ticket
 * 6. The ticket is used as MYSAPSSO2 header for subsequent ADT communication
 */

import * as http from "http"
import * as https from "https"
import { commands, Uri } from "vscode"
import { log } from "../lib"
import { RemoteConfig, formatKey } from "../config"

/**
 * Stored SSO sessions keyed by connection ID
 * Stores reentrance tickets obtained from SSO login for reuse
 */
const ssoSessions = new Map<string, SsoSession>()

interface SsoSession {
  cookies: string
  timestamp: number
}

/** SSO session validity period in milliseconds (25 minutes, slightly below typical server timeout) */
const SESSION_VALIDITY_MS = 25 * 60 * 1000

/**
 * Check if an SSO session is still valid
 */
function isSessionValid(connId: string): boolean {
  const session = ssoSessions.get(connId)
  if (!session) return false
  return Date.now() - session.timestamp < SESSION_VALIDITY_MS
}

/**
 * Get stored SSO session cookies
 */
export function getSsoSession(connId: string): string | undefined {
  const key = formatKey(connId)
  if (isSessionValid(key)) {
    return ssoSessions.get(key)?.cookies
  }
  ssoSessions.delete(key)
  return undefined
}

/**
 * Clear SSO session for a connection
 */
export function clearSsoSession(connId: string): void {
  ssoSessions.delete(formatKey(connId))
}

interface VirtualHostsResponse {
  relatedUrls: {
    UI: string
    API: string
  }
}

/**
 * Retrieve the virtual host URLs for UI and API access from the ABAP system.
 * Queries /sap/public/bc/icf/virtualhost to discover the separate UI hostname
 * (used for browser-based login) from the API hostname (used for ADT calls).
 *
 * @param apiUrl The configured API URL of the S/4HANA system
 * @returns Virtual host URLs containing separate UI and API origins
 */
async function getVirtualHosts(apiUrl: string): Promise<VirtualHostsResponse> {
  const url = new URL("/sap/public/bc/icf/virtualhost", apiUrl)
  return new Promise<VirtualHostsResponse>((resolve, reject) => {
    const req = https.get(url.href, { headers: { Accept: "application/json" } }, res => {
      let data = ""
      res.on("data", (chunk: string) => (data += chunk))
      res.on("end", () => {
        try {
          resolve(JSON.parse(data) as VirtualHostsResponse)
        } catch {
          reject(new Error(`Failed to parse virtual hosts response: ${data}`))
        }
      })
    })
    req.on("error", reject)
  })
}

const ADT_REENTRANCE_ENDPOINT = "/sap/bc/sec/reentrance"
const REDIRECT_PATH = "/redirect"
const DEFAULT_SCENARIO = "FTO1"

function redirectSuccessHtml(logoffUrl: string): string {
  const logoffLink = logoffUrl
    ? `<p><a href="${logoffUrl}" style="color:#4fc3f7">(Click here to log off the current user)</a></p>`
    : ""
  return `<html>
<head><title>Authentication Successful</title></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
display:flex;justify-content:center;align-items:center;height:100vh;
background:#1e1e1e;color:#cccccc;">
<div style="text-align:center">
<h2>&#x2705; Authentication Successful</h2>
<p>You can close this browser tab and return to VS Code.</p>
${logoffLink}
</div></body></html>`
}

function redirectErrorHtml(): string {
  return `<html>
<head><title>Authentication Failed</title></head>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
display:flex;justify-content:center;align-items:center;height:100vh;
background:#1e1e1e;color:#cccccc;">
<div style="text-align:center">
<h2>&#x274C; Authentication Failed</h2>
<p>Login failed, please check the logs in the console.</p>
</div></body></html>`
}

/**
 * Perform browser-based SSO login for S/4HANA Public Cloud.
 *
 * Opens the re-entrance ticket endpoint in a browser for the user to authenticate.
 * After IDP authentication, S/4HANA redirects back to a local HTTP server
 * with the reentrance ticket as a query parameter.
 *
 * @param conf The remote configuration for the S/4HANA Cloud connection
 * @returns A promise that resolves to the reentrance ticket value
 */
export async function s4HanaCloudLogin(conf: RemoteConfig): Promise<string> {
  const connId = formatKey(conf.name)

  // Check for existing valid session
  const existingSession = getSsoSession(connId)
  if (existingSession) {
    return existingSession
  }

  log(`🔐 Starting S/4HANA Cloud SSO login for: ${connId}`)

  // Discover the UI hostname via virtual host API.
  // S/4HANA Public Cloud exposes a separate UI URL (e.g. xxx.s4hana.ondemand.com)
  // distinct from the API URL (e.g. xxx-api.s4hana.ondemand.com).
  let uiOrigin: string
  try {
    const hosts = await getVirtualHosts(conf.url)
    uiOrigin = new URL(hosts.relatedUrls.UI).origin
    log(`🌍 Resolved UI hostname: ${uiOrigin}`)
  } catch {
    // Fall back to the configured URL if virtual host discovery fails
    uiOrigin = new URL(conf.url).origin
    log(`⚠️ Virtual host discovery failed for ${connId}, using ${uiOrigin}`)
  }

  return new Promise<string>((resolve, reject) => {
    const server = http.createServer((req, res) => {
      try {
        const reqUrl = new URL(req.url || "", `http://127.0.0.1`)

        if (reqUrl.pathname === REDIRECT_PATH) {
          const reentranceTicket = reqUrl.searchParams.get("reentrance-ticket")

          if (reentranceTicket) {
            log(`✅ S/4HANA Cloud SSO login successful for: ${connId}`)
            const logoffUrl = `${uiOrigin}/sap/public/bc/icf/logoff`
            res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" })
            res.end(redirectSuccessHtml(logoffUrl))
            clearTimeout(timeoutHandle)
            server.close()
            ssoSessions.set(connId, { cookies: reentranceTicket, timestamp: Date.now() })
            resolve(reentranceTicket)
          } else {
            log(`❌ No reentrance ticket received for: ${connId}`)
            res.writeHead(500, { "Content-Type": "text/html; charset=utf-8" })
            res.end(redirectErrorHtml())
            clearTimeout(timeoutHandle)
            server.close()
            reject(new Error("No reentrance ticket received in redirect callback"))
          }
          return
        }

        res.writeHead(200, { "Content-Type": "text/plain" })
        res.end("S/4HANA Cloud SSO Login Server")
      } catch (err) {
        log(`❌ SSO server request handler error: ${err}`)
        res.writeHead(500, { "Content-Type": "text/plain" })
        res.end("Internal Server Error")
      }
    })

    const timeoutHandle = setTimeout(() => {
      server.close()
      reject(new Error("S/4HANA Cloud SSO login timed out after 120 seconds"))
    }, 120000)

    server.listen(0, "127.0.0.1", () => {
      const address = server.address()
      if (!address || typeof address === "string") {
        clearTimeout(timeoutHandle)
        reject(new Error("Failed to start local SSO callback server"))
        return
      }

      const port = address.port
      const redirectUrl = `http://localhost:${port}${REDIRECT_PATH}`
      const scenario = process.env.FIORI_TOOLS_SCENARIO ?? DEFAULT_SCENARIO
      const endpoint = process.env.FIORI_TOOLS_REENTRANCE_ENDPOINT ?? ADT_REENTRANCE_ENDPOINT
      const loginUrl = `${uiOrigin}${endpoint}?scenario=${scenario}&redirect-url=${redirectUrl}`

      log(`🌐 Opening browser for S/4HANA Cloud SSO: ${uiOrigin}`)
      commands.executeCommand("vscode.open", Uri.parse(loginUrl))
    })

    server.on("error", err => {
      clearTimeout(timeoutHandle)
      reject(new Error(`SSO server error: ${err.message}`))
    })
  })
}

/**
 * Create an SSO login function that can be used as a BearerFetcher-like
 * callback for S/4HANA Cloud connections.
 *
 * When called, if no valid session exists, it triggers the browser-based
 * SSO flow. After IDP authentication the reentrance ticket is automatically
 * captured via the local redirect server.
 *
 * When the session expires, calling this function again will
 * trigger a new browser-based login flow.
 */
export function s4HanaCloudLoginFetcher(conf: RemoteConfig): (() => Promise<string>) | undefined {
  if (!conf.s4HanaCloud) return undefined
  return async () => {
    const connId = formatKey(conf.name)

    // Check for existing valid session
    const existingSession = getSsoSession(connId)
    if (existingSession) {
      return existingSession
    }

    // Need new SSO login
    return s4HanaCloudLogin(conf)
  }
}
