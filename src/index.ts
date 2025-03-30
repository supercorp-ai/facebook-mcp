#!/usr/bin/env node

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import express, { Request, Response } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'

// Define interfaces for Facebook user and page responses
interface FacebookUser {
  id: string
  name: string
  // Add other fields if needed
}

interface FacebookPage {
  id: string
  name: string
  access_token: string
  // Add other fields if needed
}

// --------------------------------------------------------------------
// 1) Parse CLI options (including Facebook credentials and state)
// --------------------------------------------------------------------
const argv = yargs(hideBin(process.argv))
  .option('port', { type: 'number', default: 8000 })
  .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
  .option('facebookAppId', { type: 'string', demandOption: true, describe: "Facebook App ID" })
  .option('facebookAppSecret', { type: 'string', demandOption: true, describe: "Facebook App Secret" })
  .option('facebookRedirectUri', { type: 'string', demandOption: true, describe: "Facebook Redirect URI" })
  .option('facebookState', { type: 'string', default: '', describe: "OAuth state parameter" })
  .help()
  .parseSync()

// Define log functions with explicit types
const log = (...args: any[]): void => console.log('[facebook-mcp]', ...args)
const logErr = (...args: any[]): void => console.error('[facebook-mcp]', ...args)

// --------------------------------------------------------------------
// 2) Global Facebook Auth State
// --------------------------------------------------------------------
let facebookAccessToken: string | null = null
let facebookUserId: string | null = null
// This will store a mapping of pageId -> pageAccessToken (and optionally page info)
const facebookPages: { [key: string]: string } = {}

// --------------------------------------------------------------------
// 3) Facebook OAuth Setup
// --------------------------------------------------------------------
const FACEBOOK_APP_ID: string = argv.facebookAppId
const FACEBOOK_APP_SECRET: string = argv.facebookAppSecret
const FACEBOOK_REDIRECT_URI: string = argv.facebookRedirectUri
const FACEBOOK_STATE: string = argv.facebookState

// Generate the Facebook OAuth URL.
// Now requesting these scopes:
//   public_profile, pages_show_list, pages_manage_posts, pages_read_engagement, and read_insights.
function generateFacebookAuthUrl(): string {
  const params = new URLSearchParams({
    client_id: FACEBOOK_APP_ID,
    redirect_uri: FACEBOOK_REDIRECT_URI,
    scope: 'public_profile,pages_show_list,pages_manage_posts,pages_read_engagement,read_insights',
    ...FACEBOOK_STATE ? { state: FACEBOOK_STATE } : {}
  })
  return `https://www.facebook.com/v12.0/dialog/oauth?${params.toString()}`
}

// Exchange authorization code for a user access token.
async function exchangeFacebookAuthCode(code: string): Promise<string> {
  const params = new URLSearchParams({
    client_id: FACEBOOK_APP_ID,
    redirect_uri: FACEBOOK_REDIRECT_URI,
    client_secret: FACEBOOK_APP_SECRET,
    code: code.trim()
  })
  const response = await fetch(`https://graph.facebook.com/v12.0/oauth/access_token?${params.toString()}`, {
    method: 'GET'
  })
  const data = await response.json()
  if (!data.access_token) {
    throw new Error('Failed to obtain Facebook access token.')
  }
  facebookAccessToken = data.access_token
  return data.access_token
}

// Fetch the authenticated user's basic profile (including the user ID).
async function fetchFacebookUser(): Promise<FacebookUser> {
  if (!facebookAccessToken) throw new Error('No Facebook access token available.')
  const response = await fetch(`https://graph.facebook.com/me?fields=id,name&access_token=${facebookAccessToken}`, {
    method: 'GET'
  })
  const data = await response.json()
  if (!data.id) throw new Error('Failed to fetch Facebook user id.')
  facebookUserId = data.id
  return data
}

// Authenticate with Facebook: exchange the code and fetch user info.
async function authFacebook({ code }: { code: string }): Promise<{ success: boolean; provider: string; user: FacebookUser }> {
  await exchangeFacebookAuthCode(code)
  const user = await fetchFacebookUser()
  return { success: true, provider: "facebook", user }
}

// --------------------------------------------------------------------
// 4) Tool Functions: Facebook Page Operations
// --------------------------------------------------------------------

// List all pages managed by the authenticated user.
// This calls the /me/accounts endpoint, which returns each page along with its access token.
async function listFacebookPages(): Promise<FacebookPage[]> {
  if (!facebookAccessToken) throw new Error('No Facebook access token available.')
  const response = await fetch(`https://graph.facebook.com/me/accounts?access_token=${facebookAccessToken}`, {
    method: 'GET'
  })
  const data = await response.json()
  if (!response.ok || data.error) {
    throw new Error(`Failed to fetch pages: ${data.error ? data.error.message : 'Unknown error'}`)
  }
  // Cache page access tokens for later use.
  data.data.forEach((page: FacebookPage) => {
    facebookPages[page.id] = page.access_token
  })
  return data.data
}

// Create a post on a specific page.
// Requires the caller to provide the pageId (one of the pages returned from listFacebookPages)
// and the postContent.
async function createFacebookPagePost({ pageId, postContent }: { pageId: string; postContent: string }): Promise<{ success: boolean; message: string; postId: string }> {
  if (!facebookPages[pageId]) {
    throw new Error('Page not found or not authorized. Please list pages first.')
  }
  const pageAccessToken = facebookPages[pageId]
  const postData = new URLSearchParams({
    message: postContent,
    access_token: pageAccessToken
  })
  const response = await fetch(`https://graph.facebook.com/${pageId}/feed`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: postData.toString()
  })
  const data = await response.json()
  if (!response.ok || data.error) {
    throw new Error(`Facebook page post creation failed: ${data.error ? data.error.message : 'Unknown error'}`)
  }
  return { success: true, message: 'Post created successfully.', postId: data.id }
}

// Read posts from a specific page.
// Requires the pageId and uses the stored page access token.
async function readFacebookPagePosts({ pageId }: { pageId: string }): Promise<any[]> {
  if (!facebookPages[pageId]) {
    throw new Error('Page not found or not authorized. Please list pages first.')
  }
  const pageAccessToken = facebookPages[pageId]
  const response = await fetch(`https://graph.facebook.com/${pageId}/posts?access_token=${pageAccessToken}`, {
    method: 'GET'
  })
  const data = await response.json()
  if (!response.ok || data.error) {
    throw new Error(`Failed to fetch page posts: ${data.error ? data.error.message : 'Unknown error'}`)
  }
  return data.data
}

// --------------------------------------------------------------------
// New Tool Function: Read Insights from a Facebook Page
// --------------------------------------------------------------------
// This function now supports optional since, until, and period parameters.
// Example URL:
// https://graph.facebook.com/{page-id}/insights?access_token={page-access-token}&metric=page_engaged_users,page_impressions&since=2022-07-01&until=2022-08-02&period=day,week
async function readFacebookPageInsights({
  pageId,
  metric,
  since,
  until,
  period
}: { pageId: string; metric: string[]; since?: string; until?: string; period?: string[] }): Promise<any[]> {
  if (!facebookPages[pageId]) throw new Error('Page not found or not authorized. Please list pages first.')
  const pageAccessToken = facebookPages[pageId]
  const params = new URLSearchParams({
    metric: metric.join(','),
    access_token: pageAccessToken
  })
  if (since) params.set("since", since)
  if (until) params.set("until", until)
  if (period) params.set("period", period.join(','))
  const response = await fetch(`https://graph.facebook.com/${pageId}/insights?${params.toString()}`, {
    method: 'GET'
  })
  const data = await response.json()
  if (!response.ok || data.error) {
    throw new Error(`Failed to fetch page insights: ${data.error ? data.error.message : 'Unknown error'}`)
  }
  return data.data
}

// --------------------------------------------------------------------
// 5) Helper: JSON response formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(data, null, 2)
      }
    ]
  }
}

// --------------------------------------------------------------------
// 6) Create the MCP server, registering our tools
// --------------------------------------------------------------------
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: 'Facebook MCP Server',
    version: '1.0.0'
  })

  // Tool: Return the Facebook OAuth URL.
  server.tool(
    'facebook_auth_url',
    'Return an OAuth URL for Facebook login. Use this URL to grant access with public_profile, pages_show_list, pages_manage_posts, pages_read_engagement, and read_insights scopes.',
    {},
    async () => {
      try {
        const authUrl = generateFacebookAuthUrl()
        return toTextJson({ authUrl })
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // Tool: Exchange auth code for access token and fetch user info.
  server.tool(
    'facebook_exchange_auth_code',
    'Authenticate with Facebook by exchanging an auth code. This sets up Facebook authentication.',
    {
      code: z.string()
    },
    async (args: { code: string }) => {
      try {
        const result = await authFacebook(args)
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // Tool: List pages the user manages.
  server.tool(
    'facebook_list_pages',
    'List all Pages managed by the authenticated user. Returns each page with its id and name. (Also caches the page tokens for subsequent calls.)',
    {},
    async () => {
      try {
        const pages = await listFacebookPages()
        return toTextJson({ pages })
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // Tool: Create a new post on a specific Page.
  server.tool(
    'facebook_create_page_post',
    'Create a new post on a specified Facebook Page. Provide pageId and postContent as text.',
    {
      pageId: z.string(),
      postContent: z.string()
    },
    async (args: { pageId: string; postContent: string }) => {
      try {
        const result = await createFacebookPagePost(args)
        return toTextJson(result)
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // Tool: Read posts from a specific Page.
  server.tool(
    'facebook_read_page_posts',
    'Read posts from a specified Facebook Page. Provide pageId.',
    {
      pageId: z.string()
    },
    async (args: { pageId: string }) => {
      try {
        const posts = await readFacebookPagePosts(args)
        return toTextJson({ posts })
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  // New Tool: Read insights from a specific Facebook Page.
  // Allowed metric values:
  //  "page_impressions", "page_impressions_unique", "page_engaged_users",
  //  "page_fan_adds", "page_fan_removes", "page_actions_post_reactions_total",
  //  "page_video_views", "page_posts_impressions", "page_posts_impressions_unique",
  //  "page_views_total"
  // Allowed period values: "day", "week", "days_28", "lifetime"
  server.tool(
    'facebook_read_page_insights',
    'Read insights from a specified Facebook Page. Provide pageId, a list of metrics, and optionally since, until (ISO date strings), and a list of period values. Example URL: https://graph.facebook.com/{page-id}/insights?access_token={page-access-token}&metric=page_engaged_users,page_impressions&since=2022-07-01&until=2022-08-02&period=day,week',
    {
      pageId: z.string(),
      metric: z.array(z.enum([
        "page_impressions",
        "page_impressions_unique",
        "page_engaged_users",
        "page_fan_adds",
        "page_fan_removes",
        "page_actions_post_reactions_total",
        "page_video_views",
        "page_posts_impressions",
        "page_posts_impressions_unique",
        "page_views_total"
      ])),
      since: z.string().optional(),
      until: z.string().optional(),
      period: z.array(z.enum(["day", "week", "days_28", "lifetime"])).optional()
    },
    async (args: { pageId: string; metric: string[]; since?: string; until?: string; period?: string[] }) => {
      try {
        const insights = await readFacebookPageInsights(args)
        return toTextJson({ insights })
      } catch (err: any) {
        return toTextJson({ error: String(err.message) })
      }
    }
  )

  return server
}

// --------------------------------------------------------------------
// 7) Minimal Fly.io "replay" handling (optional)
// --------------------------------------------------------------------
function parseFlyReplaySrc(headerValue: string): { [key: string]: string } {
  const regex = /(.*?)=(.*?)($|;)/g
  const matches = headerValue.matchAll(regex)
  const result: { [key: string]: string } = {}
  for (const match of matches) {
    if (match.length >= 3) {
      const key = match[1].trim()
      const value = match[2].trim()
      result[key] = value
    }
  }
  return result
}
let machineId: string | null = null
function saveMachineId(req: Request): void {
  if (machineId) return
  const headerKey = 'fly-replay-src'
  const raw = req.headers[headerKey.toLowerCase()]
  if (!raw || typeof raw !== 'string') return
  try {
    const parsed = parseFlyReplaySrc(raw)
    if (parsed.state) {
      const decoded = decodeURIComponent(parsed.state)
      const obj = JSON.parse(decoded)
      if (obj.machineId) machineId = obj.machineId
    }
  } catch {
    // ignore
  }
}

// --------------------------------------------------------------------
// 8) Main: Start either SSE or stdio server
// --------------------------------------------------------------------
function main(): void {
  const server = createMcpServer()

  if (argv.transport === 'stdio') {
    const transport = new StdioServerTransport()
    void server.connect(transport)
    log('Listening on stdio')
    return
  }

  const port = argv.port
  const app = express()
  let sessions: Array<{ server: McpServer; transport: SSEServerTransport }> = []

  app.use((req, res, next) => {
    if (req.path === '/message') return next()
    express.json()(req, res, next)
  })

  app.get('/', async (req: Request, res: Response) => {
    saveMachineId(req)
    const transport = new SSEServerTransport('/message', res)
    const mcpInstance = createMcpServer()
    await mcpInstance.connect(transport)
    sessions.push({ server: mcpInstance, transport })

    const sessionId = transport.sessionId
    log(`[${sessionId}] SSE connection established`)

    transport.onclose = () => {
      log(`[${sessionId}] SSE closed`)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    req.on('close', () => {
      log(`[${sessionId}] SSE client disconnected`)
      sessions = sessions.filter(s => s.transport !== transport)
    })
  })

  app.post('/message', async (req: Request, res: Response) => {
    const sessionId = req.query.sessionId as string
    if (!sessionId) {
      logErr('Missing sessionId')
      res.status(400).send({ error: 'Missing sessionId' })
      return
    }
    const target = sessions.find(s => s.transport.sessionId === sessionId)
    if (!target) {
      logErr(`No active session for sessionId=${sessionId}`)
      res.status(404).send({ error: 'No active session' })
      return
    }
    try {
      await target.transport.handlePostMessage(req, res)
    } catch (err: any) {
      logErr(`[${sessionId}] Error handling /message:`, err)
      res.status(500).send({ error: 'Internal error' })
    }
  })

  app.listen(port, () => {
    log(`Listening on port ${port} (${argv.transport})`)
  })
}

main()
