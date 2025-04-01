#!/usr/bin/env node

import { hideBin } from 'yargs/helpers'
import yargs from 'yargs'
import express, { Request, Response as ExpressResponse } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { Redis } from '@upstash/redis'

// --------------------------------------------------------------------
// Configuration & Storage Interface
// --------------------------------------------------------------------
interface Config {
  port: number;
  transport: 'sse' | 'stdio';
  // Storage modes: "memory-single", "memory", or "upstash-redis-rest"
  storage: 'memory-single' | 'memory' | 'upstash-redis-rest';
  facebookAppId: string;
  facebookAppSecret: string;
  facebookRedirectUri: string;
  facebookState?: string;
  // For storage "memory" and "upstash-redis-rest": the header name (or key prefix) to use.
  storageHeaderKey?: string;
  // Upstash-specific options (if storage is "upstash-redis-rest")
  upstashRedisRestUrl?: string;
  upstashRedisRestToken?: string;
}

interface Storage {
  get(memoryKey: string): Promise<Record<string, any> | undefined>;
  set(memoryKey: string, data: Record<string, any>): Promise<void>;
}

// --------------------------------------------------------------------
// In-Memory Storage Implementation
// --------------------------------------------------------------------
class MemoryStorage implements Storage {
  private storage: Record<string, Record<string, any>> = {};

  async get(memoryKey: string) {
    return this.storage[memoryKey];
  }

  async set(memoryKey: string, data: Record<string, any>) {
    this.storage[memoryKey] = { ...this.storage[memoryKey], ...data };
  }
}

// --------------------------------------------------------------------
// Upstash Redis Storage Implementation
// --------------------------------------------------------------------
class RedisStorage implements Storage {
  private redis: Redis;
  private keyPrefix: string;

  constructor(redisUrl: string, redisToken: string, keyPrefix: string) {
    this.redis = new Redis({ url: redisUrl, token: redisToken });
    this.keyPrefix = keyPrefix;
  }

  async get(memoryKey: string): Promise<Record<string, any> | undefined> {
    const data = await this.redis.get<Record<string, any>>(`${this.keyPrefix}:${memoryKey}`);
    return data === null ? undefined : data;
  }

  async set(memoryKey: string, data: Record<string, any>) {
    const existing = (await this.get(memoryKey)) || {};
    const newData = { ...existing, ...data };
    await this.redis.set(`${this.keyPrefix}:${memoryKey}`, JSON.stringify(newData));
  }
}

// --------------------------------------------------------------------
// Facebook OAuth Helper Functions
// --------------------------------------------------------------------
function generateFacebookAuthUrl(config: Config): string {
  const params = new URLSearchParams({
    client_id: config.facebookAppId,
    redirect_uri: config.facebookRedirectUri,
    scope: 'public_profile,pages_show_list,pages_manage_posts,pages_read_engagement,read_insights'
  });
  // Include state if provided.
  if (config.facebookState && config.facebookState.trim()) {
    params.set('state', config.facebookState.trim());
  }
  return `https://www.facebook.com/v12.0/dialog/oauth?${params.toString()}`;
}

async function exchangeFacebookAuthCode(code: string, config: Config, storage: Storage, memoryKey: string): Promise<string> {
  const params = new URLSearchParams({
    client_id: config.facebookAppId,
    redirect_uri: config.facebookRedirectUri,
    client_secret: config.facebookAppSecret,
    code: code.trim()
  });
  const response = await fetch(`https://graph.facebook.com/v12.0/oauth/access_token?${params.toString()}`, {
    method: 'GET'
  });
  const data = await response.json();
  if (!data.access_token) {
    throw new Error('Failed to obtain Facebook access token.');
  }
  // Store access token in storage.
  await storage.set(memoryKey, { accessToken: data.access_token });
  return data.access_token;
}

async function fetchFacebookUser(config: Config, storage: Storage, memoryKey: string): Promise<{ id: string; name: string }> {
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.accessToken) {
    throw new Error('No Facebook access token available.');
  }
  const response = await fetch(`https://graph.facebook.com/me?fields=id,name&access_token=${stored.accessToken}`, {
    method: 'GET'
  });
  const data = await response.json();
  if (!data.id) {
    throw new Error('Failed to fetch Facebook user id.');
  }
  await storage.set(memoryKey, { userId: data.id });
  return data;
}

async function authFacebook(args: { code: string; config: Config; storage: Storage; memoryKey: string }): Promise<{ success: boolean; provider: string; user: { id: string; name: string } }> {
  const { code, config, storage, memoryKey } = args;
  await exchangeFacebookAuthCode(code, config, storage, memoryKey);
  const user = await fetchFacebookUser(config, storage, memoryKey);
  return { success: true, provider: "facebook", user };
}

// --------------------------------------------------------------------
// Facebook Page Operations
// --------------------------------------------------------------------
interface FacebookPage {
  id: string;
  name: string;
  access_token: string;
  // Other fields if needed.
}

async function listFacebookPages(config: Config, storage: Storage, memoryKey: string): Promise<FacebookPage[]> {
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.accessToken) {
    throw new Error('No Facebook access token available.');
  }
  const response = await fetch(`https://graph.facebook.com/me/accounts?access_token=${stored.accessToken}`, {
    method: 'GET'
  });
  const data = await response.json();
  if (!response.ok || data.error) {
    throw new Error(`Failed to fetch pages: ${data.error ? data.error.message : 'Unknown error'}`);
  }
  // Cache pages in storage under "pages"
  // Create a mapping: pageId -> pageAccessToken
  const pages: { [key: string]: string } = {};
  for (const page of data.data) {
    pages[page.id] = page.access_token;
  }
  await storage.set(memoryKey, { pages });
  return data.data;
}

async function createFacebookPagePost(args: { pageId: string; postContent: string; config: Config; storage: Storage; memoryKey: string }): Promise<{ success: boolean; message: string; postId: string }> {
  const { pageId, postContent, config, storage, memoryKey } = args;
  const stored = await storage.get(memoryKey);
  const pages = stored?.pages;
  if (!pages || !pages[pageId]) {
    throw new Error('Page not found or not authorized. Please list pages first.');
  }
  const pageAccessToken = pages[pageId];
  const postData = new URLSearchParams({
    message: postContent,
    access_token: pageAccessToken
  });
  const response = await fetch(`https://graph.facebook.com/${pageId}/feed`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: postData.toString()
  });
  const data = await response.json();
  if (!response.ok || data.error) {
    throw new Error(`Facebook page post creation failed: ${data.error ? data.error.message : 'Unknown error'}`);
  }
  return { success: true, message: 'Post created successfully.', postId: data.id };
}

async function readFacebookPagePosts(args: { pageId: string; config: Config; storage: Storage; memoryKey: string }): Promise<any[]> {
  const { pageId, config, storage, memoryKey } = args;
  const stored = await storage.get(memoryKey);
  const pages = stored?.pages;
  if (!pages || !pages[pageId]) {
    throw new Error('Page not found or not authorized. Please list pages first.');
  }
  const pageAccessToken = pages[pageId];
  const response = await fetch(`https://graph.facebook.com/${pageId}/posts?access_token=${pageAccessToken}`, {
    method: 'GET'
  });
  const data = await response.json();
  if (!response.ok || data.error) {
    throw new Error(`Failed to fetch page posts: ${data.error ? data.error.message : 'Unknown error'}`);
  }
  return data.data;
}

async function readFacebookPageInsights(args: { pageId: string; metric: string[]; since?: string; until?: string; period?: string[]; config: Config; storage: Storage; memoryKey: string }): Promise<any[]> {
  const { pageId, metric, since, until, period, config, storage, memoryKey } = args;
  const stored = await storage.get(memoryKey);
  const pages = stored?.pages;
  if (!pages || !pages[pageId]) {
    throw new Error('Page not found or not authorized. Please list pages first.');
  }
  const pageAccessToken = pages[pageId];
  const params = new URLSearchParams({
    metric: metric.join(','),
    access_token: pageAccessToken
  });
  if (since) params.set("since", since);
  if (until) params.set("until", until);
  if (period) params.set("period", period.join(','));
  const response = await fetch(`https://graph.facebook.com/${pageId}/insights?${params.toString()}`, {
    method: 'GET'
  });
  const data = await response.json();
  if (!response.ok || data.error) {
    throw new Error(`Failed to fetch page insights: ${data.error ? data.error.message : 'Unknown error'}`);
  }
  return data.data;
}

// --------------------------------------------------------------------
// Helper: JSON Response Formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(data, null, 2)
      }
    ]
  };
}

// --------------------------------------------------------------------
// Create an MCP server and register Facebook tools
// --------------------------------------------------------------------
function createMcpServer(memoryKey: string, config: Config): McpServer {
  const server = new McpServer({
    name: `Facebook MCP Server (Memory Key: ${memoryKey})`,
    version: '1.0.0'
  });

  server.tool(
    'facebook_auth_url',
    'Return an OAuth URL for Facebook login. Use this URL to grant access with public_profile, pages_show_list, pages_manage_posts, pages_read_engagement, and read_insights scopes.',
    {},
    async () => {
      try {
        const authUrl = generateFacebookAuthUrl(config);
        return toTextJson({ authUrl });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'facebook_exchange_auth_code',
    'Authenticate with Facebook by exchanging an auth code. This sets up Facebook authentication.',
    { code: z.string() },
    async (args: { code: string }) => {
      try {
        const result = await authFacebook({ code: args.code, config, storage: getStorage(config), memoryKey });
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'facebook_list_pages',
    'List all Pages managed by the authenticated user. Returns each page with its id and name. (Also caches page tokens for subsequent calls.)',
    {},
    async () => {
      try {
        const pages = await listFacebookPages(config, getStorage(config), memoryKey);
        return toTextJson({ pages });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'facebook_create_page_post',
    'Create a new post on a specified Facebook Page. Provide pageId and postContent as text.',
    { pageId: z.string(), postContent: z.string() },
    async (args: { pageId: string; postContent: string }) => {
      try {
        const result = await createFacebookPagePost({ pageId: args.pageId, postContent: args.postContent, config, storage: getStorage(config), memoryKey });
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'facebook_read_page_posts',
    'Read posts from a specified Facebook Page. Provide pageId.',
    { pageId: z.string() },
    async (args: { pageId: string }) => {
      try {
        const posts = await readFacebookPagePosts({ pageId: args.pageId, config, storage: getStorage(config), memoryKey });
        return toTextJson({ posts });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    'facebook_read_page_insights',
    'Read insights from a specified Facebook Page. Provide pageId, a list of metrics, and optionally since, until (ISO date strings), and a list of period values.',
    {
      pageId: z.string(),
      metric: z.array(z.string()),
      since: z.string().optional(),
      until: z.string().optional(),
      period: z.array(z.string()).optional()
    },
    async (args: { pageId: string; metric: string[]; since?: string; until?: string; period?: string[] }) => {
      try {
        const insights = await readFacebookPageInsights({ ...args, config, storage: getStorage(config), memoryKey });
        return toTextJson({ insights });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  return server;
}

// Helper to create the correct Storage instance based on config.
function getStorage(config: Config): Storage {
  if (config.storage === 'upstash-redis-rest') {
    return new RedisStorage(
      config.upstashRedisRestUrl!,
      config.upstashRedisRestToken!,
      config.storageHeaderKey!
    );
  }
  return new MemoryStorage();
}

// --------------------------------------------------------------------
// Main: Start the server (SSE or stdio)
// --------------------------------------------------------------------
function main(): void {
  const argv = yargs(hideBin(process.argv))
    .option('port', { type: 'number', default: 8000 })
    .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
    .option('storage', {
      type: 'string',
      choices: ['memory-single', 'memory', 'upstash-redis-rest'],
      default: 'memory-single',
      describe:
        'Choose storage backend: "memory-single" uses fixed single-user storage; "memory" uses multi-user in-memory storage (requires --storageHeaderKey); "upstash-redis-rest" uses Upstash Redis (requires --storageHeaderKey, --upstashRedisRestUrl, and --upstashRedisRestToken).'
    })
    .option('facebookAppId', { type: 'string', demandOption: true, describe: "Facebook App ID" })
    .option('facebookAppSecret', { type: 'string', demandOption: true, describe: "Facebook App Secret" })
    .option('facebookRedirectUri', { type: 'string', demandOption: true, describe: "Facebook Redirect URI" })
    .option('facebookState', { type: 'string', describe: "Optional OAuth state parameter" })
    .option('storageHeaderKey', { type: 'string', describe: 'For storage "memory" or "upstash-redis-rest": the header name (or key prefix) to use.' })
    .option('upstashRedisRestUrl', { type: 'string', describe: 'Upstash Redis REST URL (if --storage=upstash-redis-rest)' })
    .option('upstashRedisRestToken', { type: 'string', describe: 'Upstash Redis REST token (if --storage=upstash-redis-rest)' })
    .help()
    .parseSync();

  const config: Config = {
    port: argv.port,
    transport: argv.transport as 'sse' | 'stdio',
    storage: argv.storage as 'memory-single' | 'memory' | 'upstash-redis-rest',
    facebookAppId: argv.facebookAppId,
    facebookAppSecret: argv.facebookAppSecret,
    facebookRedirectUri: argv.facebookRedirectUri,
    facebookState: argv.facebookState,
    storageHeaderKey:
      (argv.storage === 'memory-single')
        ? undefined
        : (argv.storageHeaderKey && argv.storageHeaderKey.trim()
          ? argv.storageHeaderKey.trim()
          : (() => { console.error('Error: --storageHeaderKey is required for storage modes "memory" or "upstash-redis-rest".'); process.exit(1); return ''; })()),
    upstashRedisRestUrl: argv.upstashRedisRestUrl,
    upstashRedisRestToken: argv.upstashRedisRestToken,
  };

  if (config.storage === 'upstash-redis-rest') {
    if (!config.upstashRedisRestUrl || !config.upstashRedisRestUrl.trim()) {
      console.error("Error: --upstashRedisRestUrl is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
    if (!config.upstashRedisRestToken || !config.upstashRedisRestToken.trim()) {
      console.error("Error: --upstashRedisRestToken is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
  }

  if (config.transport === 'stdio') {
    const memoryKey = "single";
    const server = createMcpServer(memoryKey, config);
    const transport = new StdioServerTransport();
    void server.connect(transport);
    console.log('Listening on stdio');
    return;
  }

  const app = express();
  interface ServerSession {
    memoryKey: string;
    server: McpServer;
    transport: SSEServerTransport;
    sessionId: string;
  }
  let sessions: ServerSession[] = [];

  // Use JSON parser for non-/message routes.
  app.use((req, res, next) => {
    if (req.path === '/message') return next();
    express.json()(req, res, next);
  });

  app.get('/', async (req: Request, res: ExpressResponse) => {
    let memoryKey: string;
    if (config.storage === 'memory-single') {
      memoryKey = "single";
    } else {
      const headerVal = req.headers[config.storageHeaderKey!.toLowerCase()];
      if (typeof headerVal !== 'string' || !headerVal.trim()) {
        res.status(400).json({ error: `Missing or invalid "${config.storageHeaderKey}" header` });
        return;
      }
      memoryKey = headerVal.trim();
    }
    const server = createMcpServer(memoryKey, config);
    const transport = new SSEServerTransport('/message', res);
    await server.connect(transport);
    const sessionId = transport.sessionId;
    sessions.push({ memoryKey, server, transport, sessionId });
    console.log(`[${sessionId}] SSE connected for key: "${memoryKey}"`);
    transport.onclose = () => {
      console.log(`[${sessionId}] SSE connection closed`);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    transport.onerror = (err: Error) => {
      console.error(`[${sessionId}] SSE error:`, err);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    req.on('close', () => {
      console.log(`[${sessionId}] Client disconnected`);
      sessions = sessions.filter(s => s.transport !== transport);
    });
  });

  app.post('/message', async (req: Request, res: ExpressResponse) => {
    const sessionId = req.query.sessionId as string;
    if (!sessionId) {
      console.error('Missing sessionId');
      res.status(400).send({ error: 'Missing sessionId' });
      return;
    }
    const target = sessions.find(s => s.sessionId === sessionId);
    if (!target) {
      console.error(`No active session for sessionId=${sessionId}`);
      res.status(404).send({ error: 'No active session' });
      return;
    }
    try {
      await target.transport.handlePostMessage(req, res);
    } catch (err: any) {
      console.error(`[${sessionId}] Error handling /message:`, err);
      res.status(500).send({ error: 'Internal error' });
    }
  });

  app.listen(config.port, () => {
    console.log(`Listening on port ${config.port} (${argv.transport})`);
  });
}

main();
