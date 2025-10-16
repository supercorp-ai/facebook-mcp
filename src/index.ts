#!/usr/bin/env node

import { hideBin } from 'yargs/helpers'
import yargs from 'yargs'
import express, { Request, Response as ExpressResponse } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { InMemoryEventStore } from '@modelcontextprotocol/sdk/examples/shared/inMemoryEventStore.js'
import { z } from 'zod'
import { Redis } from '@upstash/redis'
import { randomUUID } from 'node:crypto'

// --------------------------------------------------------------------
// Configuration & Storage Interface
// --------------------------------------------------------------------
interface Config {
  port: number;
  transport: 'sse' | 'stdio' | 'http';
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
    const data = await this.redis.get(`${this.keyPrefix}:${memoryKey}`);
    return data === null ? undefined : (typeof data === 'string' ? JSON.parse(data) : data);
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
    // scope: 'public_profile,pages_show_list,pages_manage_posts,pages_read_engagement,read_insights'
    scope: 'public_profile,pages_show_list,pages_manage_posts,pages_read_engagement'
  });
  if (config.facebookState && config.facebookState.trim()) {
    params.set('state', config.facebookState.trim());
  }
  return `https://www.facebook.com/v12.0/dialog/oauth?${params.toString()}`;
}

// Exchange a short-lived user access token for a long-lived user token (~60 days)
async function exchangeToLongLivedUserToken(
  shortLivedToken: string,
  config: Config
): Promise<{ access_token: string; token_type?: string; expires_in?: number }> {
  const params = new URLSearchParams({
    grant_type: 'fb_exchange_token',
    client_id: config.facebookAppId,
    client_secret: config.facebookAppSecret,
    fb_exchange_token: shortLivedToken,
  });
  const resp = await fetch(`https://graph.facebook.com/v12.0/oauth/access_token?${params.toString()}`, {
    method: 'GET',
  });
  const data = await resp.json();
  if (!resp.ok || !data.access_token) {
    const msg = data?.error?.message || 'Failed to exchange for long-lived token';
    throw new Error(msg);
  }
  return data;
}

// Inspect token metadata using Graph API debug_token
type TokenDebug = { expires_at?: number; data_access_expires_at?: number; is_valid?: boolean; type?: string; issued_at?: number; user_id?: string };
async function debugFacebookToken(token: string, config: Config): Promise<TokenDebug | undefined> {
  const appAccessToken = `${config.facebookAppId}|${config.facebookAppSecret}`;
  const params = new URLSearchParams({ input_token: token, access_token: appAccessToken });
  const versions = ['v12.0', 'v17.0'];
  for (const ver of versions) {
    try {
      const url = `https://graph.facebook.com/${ver}/debug_token?${params.toString()}`;
      const resp = await fetch(url, { method: 'GET' });
      const info = await resp.json();
      if (!resp.ok || !info?.data) {
        console.warn(`[facebook-mcp] debug_token (${ver}) failed or missing data:`, info?.error || info);
        continue;
      }
      const data = info.data as TokenDebug;
      console.log(`[facebook-mcp] debug_token ${ver}: is_valid=${data?.is_valid} type=${data?.type} user_id=${data?.user_id} expires_at=${data?.expires_at ?? 'n/a'} data_access_expires_at=${data?.data_access_expires_at ?? 'n/a'}`);
      return data;
    } catch (e) {
      console.warn(`[facebook-mcp] debug_token (${ver}) error:`, e);
    }
  }
  return undefined;
}

// Ensure we have a long-lived user token stored at key `accessToken`.
// Backward-compatible: if no expires info exists, attempt upgrade in-place.
async function ensureLongLivedUserToken(
  storage: Storage,
  memoryKey: string,
  config: Config
): Promise<string> {
  const stored = await storage.get(memoryKey);
  if (!stored || !stored.accessToken) {
    throw new Error('No Facebook access token available.');
  }

  // Sanitize and persist token if needed
  const sanitized = sanitizeToken(stored.accessToken);
  if (sanitized !== stored.accessToken) {
    await storage.set(memoryKey, { accessToken: sanitized });
    console.log('[facebook-mcp] Sanitized accessToken (removed trailing fragments).');
  }

  const now = Date.now();
  const expiresAt: number | undefined = stored.accessTokenExpiresAt;

  if (!expiresAt) {
    console.log('[facebook-mcp] accessToken has no expiresAt; attempting to determine/upgrade.');
  }

  // If we already have a future expiry, consider it long-lived; extend if close to expiry (<7 days)
  if (expiresAt && expiresAt > now) {
    const sevenDays = 7 * 24 * 60 * 60 * 1000;
    if (expiresAt - now < sevenDays) {
      try {
        console.log('[facebook-mcp] accessToken near expiry; extending via fb_exchange_token.');
        const exchanged = await exchangeToLongLivedUserToken(sanitized, config);
        const newExpiresAt = exchanged.expires_in ? now + exchanged.expires_in * 1000 : undefined;
        await storage.set(memoryKey, {
          accessToken: exchanged.access_token,
          accessTokenType: exchanged.token_type || stored.accessTokenType,
          accessTokenExpiresAt: newExpiresAt,
        });
        if (!newExpiresAt) {
          // Attempt to fetch expires_at via debug_token as fallback
          const meta = await debugFacebookToken(exchanged.access_token, config);
          if (meta?.expires_at) {
            await storage.set(memoryKey, { accessTokenExpiresAt: meta.expires_at * 1000 });
            console.log('[facebook-mcp] Updated accessTokenExpiresAt from debug_token after extension.');
          }
        }
        return exchanged.access_token;
      } catch (e) {
        // If extend fails, fall back to existing token (may still be valid until expiresAt)
        console.warn('[facebook-mcp] fb_exchange_token failed near expiry; using existing token.', e);
        return stored.accessToken;
      }
    }
    return stored.accessToken;
  }

  // Legacy or short-lived without expiry: attempt an upgrade.
  try {
    console.log('[facebook-mcp] Upgrading accessToken to long-lived via fb_exchange_token.');
    const exchanged = await exchangeToLongLivedUserToken(sanitized, config);
    const newExpiresAt = exchanged.expires_in ? now + exchanged.expires_in * 1000 : undefined;
    await storage.set(memoryKey, {
      accessToken: exchanged.access_token,
      accessTokenType: exchanged.token_type,
      accessTokenExpiresAt: newExpiresAt,
      // keep any other stored fields intact via Storage.set implementation
    });
    if (!newExpiresAt) {
      // Fallback: query debug_token to persist expiry if available
      const meta = await debugFacebookToken(exchanged.access_token, config);
      if (meta?.expires_at) {
        await storage.set(memoryKey, { accessTokenExpiresAt: meta.expires_at * 1000 });
        console.log('[facebook-mcp] Stored accessTokenExpiresAt from debug_token after upgrade.');
      } else if (typeof meta?.data_access_expires_at === 'number') {
        await storage.set(memoryKey, { accessTokenDataAccessExpiresAt: meta.data_access_expires_at * 1000 });
        console.log('[facebook-mcp] Stored accessTokenDataAccessExpiresAt from debug_token after upgrade.');
      } else {
        console.log('[facebook-mcp] Long-lived token obtained but expires_in not provided by API.');
      }
    }
    return exchanged.access_token;
  } catch (e) {
    // If exchange fails (e.g., token already long-lived or invalid), keep original to preserve compatibility
    console.warn('[facebook-mcp] fb_exchange_token upgrade failed; attempting to fetch expiry via debug_token.', e);
    const meta = await debugFacebookToken(sanitized, config);
    if (meta?.expires_at) {
      await storage.set(memoryKey, { accessTokenExpiresAt: meta.expires_at * 1000 });
      console.log('[facebook-mcp] Stored accessTokenExpiresAt from debug_token (original token).');
    } else if (typeof meta?.data_access_expires_at === 'number') {
      await storage.set(memoryKey, { accessTokenDataAccessExpiresAt: meta.data_access_expires_at * 1000 });
      console.log('[facebook-mcp] Stored accessTokenDataAccessExpiresAt from debug_token (original token).');
    }
    return stored.accessToken;
  }
}

async function exchangeFacebookAuthCode(
  code: string,
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<string> {
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
  // Immediately upgrade to a long-lived user access token for durability
  let finalAccessToken = data.access_token as string;
  try {
    console.log('[facebook-mcp] Exchanging short-lived user token for long-lived token.');
    const exchanged = await exchangeToLongLivedUserToken(data.access_token, config);
    finalAccessToken = sanitizeToken(exchanged.access_token);
    const now = Date.now();
    const newExpiresAt = exchanged.expires_in ? now + exchanged.expires_in * 1000 : undefined;
    await storage.set(memoryKey, {
      accessToken: finalAccessToken,
      accessTokenType: exchanged.token_type,
      accessTokenExpiresAt: newExpiresAt,
    });
    if (!newExpiresAt) {
      const meta = await debugFacebookToken(finalAccessToken, config);
      if (meta?.expires_at) {
        await storage.set(memoryKey, { accessTokenExpiresAt: meta.expires_at * 1000 });
        console.log('[facebook-mcp] Stored accessTokenExpiresAt from debug_token after initial exchange.');
      } else if (typeof meta?.data_access_expires_at === 'number') {
        await storage.set(memoryKey, { accessTokenDataAccessExpiresAt: meta.data_access_expires_at * 1000 });
        console.log('[facebook-mcp] Stored accessTokenDataAccessExpiresAt from debug_token (no token expiry reported).');
      } else {
        console.log('[facebook-mcp] Exchange succeeded, but API did not include expires_in; no expiry saved.');
      }
    } else {
      console.log('[facebook-mcp] Stored long-lived token with expires_in seconds =', exchanged.expires_in);
    }
  } catch {
    // If exchange fails, store short-lived token (backward compatible)
    console.warn('[facebook-mcp] Long-lived exchange failed; storing short-lived token.');
    await storage.set(memoryKey, { accessToken: finalAccessToken });
    // Try to fetch expiry metadata anyway
    const meta = await debugFacebookToken(finalAccessToken, config);
    if (meta?.expires_at) {
      await storage.set(memoryKey, { accessTokenExpiresAt: meta.expires_at * 1000 });
      console.log('[facebook-mcp] Stored accessTokenExpiresAt from debug_token (short-lived).');
    } else if (typeof meta?.data_access_expires_at === 'number') {
      await storage.set(memoryKey, { accessTokenDataAccessExpiresAt: meta.data_access_expires_at * 1000 });
      console.log('[facebook-mcp] Stored accessTokenDataAccessExpiresAt from debug_token (short-lived).');
    }
  }
  return finalAccessToken;
}

async function fetchFacebookUser(
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<{ id: string; name: string }> {
  // Ensure we use a long-lived user token; auto-upgrade legacy short tokens.
  const accessToken = await ensureLongLivedUserToken(storage, memoryKey, config);
  const url = new URL('https://graph.facebook.com/me');
  url.search = new URLSearchParams({ fields: 'id,name', access_token: accessToken }).toString();
  const response = await fetch(url, { method: 'GET' });
  const data = await response.json();
  if (!data.id) {
    throw new Error('Failed to fetch Facebook user id.');
  }
  await storage.set(memoryKey, { userId: data.id });
  return data;
}

async function authFacebook(
  args: { code: string; config: Config; storage: Storage; memoryKey: string }
): Promise<{ success: boolean; provider: string; user: { id: string; name: string } }> {
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
}

async function listFacebookPages(
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<FacebookPage[]> {
  const accessToken = await ensureLongLivedUserToken(storage, memoryKey, config);
  console.log('[facebook-mcp] Fetching /me/accounts to refresh Page tokens.');
  const url = new URL('https://graph.facebook.com/me/accounts');
  url.search = new URLSearchParams({ access_token: accessToken }).toString();
  const response = await fetch(url, { method: 'GET' });
  const data = await response.json();
  if (!response.ok || data.error) {
    throw new Error(`Failed to fetch pages: ${data.error ? data.error.message : 'Unknown error'}`);
  }
  const pages: { [key: string]: string } = {};
  for (const page of data.data) {
    pages[page.id] = page.access_token;
  }
  await storage.set(memoryKey, { pages });
  console.log(`[facebook-mcp] Cached ${data.data?.length ?? 0} Page tokens.`);
  return data.data;
}

// Reusable helper to obtain a Page access token. If not cached, refreshes pages once.
async function getPageAccessTokenFor(
  pageId: string,
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<string> {
  let stored = await storage.get(memoryKey);
  let pages = stored?.pages as { [key: string]: string } | undefined;
  if (!pages || !pages[pageId]) {
    console.log(`[facebook-mcp] No cached Page token for ${pageId}; refreshing …`);
    await listFacebookPages(config, storage, memoryKey);
    stored = await storage.get(memoryKey);
    pages = stored?.pages as { [key: string]: string } | undefined;
  }
  const token = pages?.[pageId];
  if (!token || !String(token).trim()) {
    throw new Error('Page not found or not authorized. Please list pages first.');
  }
  return token;
}

/**
 * Create a new post on a Facebook Page.
 * If an optional imageUrl is provided, post to /photos endpoint; otherwise post to /feed.
 */
async function createFacebookPagePost(
  args: { pageId: string; postContent: string; imageUrl?: string; config: Config; storage: Storage; memoryKey: string }
): Promise<{ success: boolean; message: string; postId: string }> {
  const { pageId, postContent, imageUrl, config, storage, memoryKey } = args;
  let pageAccessToken = await getPageAccessTokenFor(pageId, config, storage, memoryKey);
  let url: string;
  let params: URLSearchParams;

  if (imageUrl && imageUrl.trim()) {
    // Post an image: use the /photos endpoint.
    url = `https://graph.facebook.com/${pageId}/photos`;
    params = new URLSearchParams({
      url: imageUrl,
      caption: postContent,
      access_token: pageAccessToken
    });
  } else {
    // Regular text post: use the /feed endpoint.
    url = `https://graph.facebook.com/${pageId}/feed`;
    params = new URLSearchParams({
      message: postContent,
      access_token: pageAccessToken
    });
  }

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString()
  });
  const data = await response.json();
  if (!response.ok || data.error) {
    // If token invalid/expired, refresh page tokens once and retry
    if (isLikelyTokenError(data)) {
      console.warn('[facebook-mcp] Token error posting to Page; refreshing Page token and retrying once.');
      try {
        pageAccessToken = await getPageAccessTokenFor(pageId, config, storage, memoryKey);
        params.set('access_token', pageAccessToken);
        const retryResp = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: params.toString(),
        });
        const retryData = await retryResp.json();
        if (retryResp.ok && !retryData.error) {
          console.log('[facebook-mcp] Retry succeeded for Page post.');
          return { success: true, message: 'Post created successfully.', postId: retryData.id };
        }
      } catch {}
    }
    throw new Error(`Facebook page post creation failed: ${data.error ? data.error.message : 'Unknown error'}`);
  }
  return { success: true, message: 'Post created successfully.', postId: data.id };
}

async function readFacebookPagePosts(
  args: { pageId: string; config: Config; storage: Storage; memoryKey: string }
): Promise<any[]> {
  const { pageId, config, storage, memoryKey } = args;
  const pageAccessToken = await getPageAccessTokenFor(pageId, config, storage, memoryKey);
  const url = new URL(`https://graph.facebook.com/${pageId}/posts`);
  url.search = new URLSearchParams({ access_token: pageAccessToken }).toString();
  const response = await fetch(url, { method: 'GET' });
  const data = await response.json();
  if (!response.ok || data.error) {
    if (isLikelyTokenError(data)) {
      console.warn('[facebook-mcp] Token error reading Page posts; refreshing Page token and retrying once.');
      try {
        const refreshedToken = await getPageAccessTokenFor(pageId, config, storage, memoryKey);
        const retryUrl = new URL(`https://graph.facebook.com/${pageId}/posts`);
        retryUrl.search = new URLSearchParams({ access_token: refreshedToken }).toString();
        const retryResp = await fetch(retryUrl, { method: 'GET' });
        const retryData = await retryResp.json();
        if (retryResp.ok && !retryData.error) {
          console.log('[facebook-mcp] Retry succeeded for Page posts read.');
          return retryData.data;
        }
      } catch {}
    }
    throw new Error(`Failed to fetch page posts: ${data.error ? data.error.message : 'Unknown error'}`);
  }
  return data.data;
}

// --------------------------------------------------------------------
// Helper: JSON Response Formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [
      { type: 'text', text: JSON.stringify(data, null, 2) }
    ]
  };
}

// Helper: detect token-related errors from Facebook Graph API responses
function isLikelyTokenError(data: any): boolean {
  const err = data?.error;
  if (!err) return false;
  const msg: string = (err?.message ?? '').toString();
  const code: number | undefined = typeof err?.code === 'number' ? err.code : undefined;
  const subcode: number | undefined = typeof err?.error_subcode === 'number' ? err.error_subcode : undefined;
  return msg.includes('Invalid OAuth access token') || code === 190 || typeof subcode === 'number';
}

// Helper: sanitize token values copied from URLs (e.g., trailing "#_=_")
function sanitizeToken(token: string): string {
  return token.trim().replace(/#_=_$/, '');
}


// --------------------------------------------------------------------
// Create an MCP server and register Facebook tools with toolsPrefix support
// --------------------------------------------------------------------
function createMcpServer(memoryKey: string, config: Config, toolsPrefix: string): McpServer {
  const server = new McpServer({
    name: `Facebook MCP Server (Memory Key: ${memoryKey})`,
    version: '1.0.0'
  });

  server.tool(
    `${toolsPrefix}auth_url`,
    'Return an OAuth URL for Facebook login.',
    {
      // TODO: MCP SDK bug patch - remove when fixed
      comment: z.string().optional(),
    },
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
    `${toolsPrefix}exchange_auth_code`,
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
    `${toolsPrefix}list_pages`,
    'List all Pages managed by the authenticated user. Returns each page with its id and name.',
    {
      // TODO: MCP SDK bug patch - remove when fixed
      comment: z.string().optional(),
    },
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
    `${toolsPrefix}create_page_post`,
    'Create a new post on a specified Facebook Page. Provide pageId and postContent as text. Optionally, provide imageUrl to post an image.',
    { pageId: z.string(), postContent: z.string(), imageUrl: z.string().optional() },
    async (args: { pageId: string; postContent: string; imageUrl?: string }) => {
      try {
        const result = await createFacebookPagePost({ pageId: args.pageId, postContent: args.postContent, imageUrl: args.imageUrl, config, storage: getStorage(config), memoryKey });
        return toTextJson(result);
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}read_page_posts`,
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
    // Note: storageHeaderKey is used as the key prefix for Upstash
  }
  return new MemoryStorage();
}

// --------------------------------------------------------------------
// Main: Start the server (HTTP / SSE / stdio) with CLI validations
// --------------------------------------------------------------------
async function main() {
  const argv = yargs(hideBin(process.argv))
    .option('port', { type: 'number', default: 8000 })
    .option('transport', { type: 'string', choices: ['sse', 'stdio', 'http'], default: 'sse' })
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
    .option('toolsPrefix', { type: 'string', default: 'facebook_', describe: 'Prefix to add to all tool names.' })
    .option('storageHeaderKey', { type: 'string', describe: 'For storage "memory" or "upstash-redis-rest": the header name (or key prefix) to use.' })
    .option('upstashRedisRestUrl', { type: 'string', describe: 'Upstash Redis REST URL (if --storage=upstash-redis-rest)' })
    .option('upstashRedisRestToken', { type: 'string', describe: 'Upstash Redis REST token (if --storage=upstash-redis-rest)' })
    .help()
    .parseSync();

  const config: Config = {
    port: argv.port,
    transport: argv.transport as 'sse' | 'stdio' | 'http',
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

  const toolsPrefix: string = argv.toolsPrefix;

  // stdio
  if (config.transport === 'stdio') {
    const memoryKey = "single";
    const server = createMcpServer(memoryKey, config, toolsPrefix);
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.log('Listening on stdio');
    return;
  }

  // Streamable HTTP (root "/")
  if (config.transport === 'http') {
    const app = express();

    // Do not JSON-parse "/" — the transport handles raw body/streaming
    app.use((req, res, next) => {
      if (req.path === '/') return next();
      express.json()(req, res, next);
    });

    interface HttpSession {
      memoryKey: string;
      server: McpServer;
      transport: StreamableHTTPServerTransport;
    }
    const sessions = new Map<string, HttpSession>();

    function resolveMemoryKeyFromHeaders(req: Request): string | undefined {
      if (config.storage === 'memory-single') return 'single';
      const keyName = (config.storageHeaderKey as string).toLowerCase();
      const headerVal = req.headers[keyName];
      if (typeof headerVal !== 'string' || !headerVal.trim()) return undefined;
      return headerVal.trim();
    }

    function createServerFor(memoryKey: string) {
      return createMcpServer(memoryKey, config, toolsPrefix);
    }

    // POST / — JSON-RPC input; initializes a session if none exists
    app.post('/', async (req: Request, res: ExpressResponse) => {
      try {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;

        if (sessionId && sessions.has(sessionId)) {
          const { transport } = sessions.get(sessionId)!;
          await transport.handleRequest(req, res);
          return;
        }

        // New initialization — require a valid memoryKey (no anonymous)
        const memoryKey = resolveMemoryKeyFromHeaders(req);
        if (!memoryKey) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: `Bad Request: Missing or invalid "${config.storageHeaderKey}" header` },
            id: (req as any)?.body?.id
          });
          return;
        }

        const server = createServerFor(memoryKey);
        const eventStore = new InMemoryEventStore();

        let transport!: StreamableHTTPServerTransport;
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          eventStore,
          onsessioninitialized: (newSessionId: string) => {
            sessions.set(newSessionId, { memoryKey, server, transport });
            console.log(`[${newSessionId}] HTTP session initialized for key "${memoryKey}"`);
          }
        });

        transport.onclose = async () => {
          const sid = transport.sessionId;
          if (sid && sessions.has(sid)) {
            sessions.delete(sid);
            console.log(`[${sid}] Transport closed; removed session`);
          }
          try { await server.close(); } catch { /* already closed */ }
        };

        await server.connect(transport);
        await transport.handleRequest(req, res);
      } catch (err) {
        console.error('Error handling HTTP POST /:', err);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: (req as any)?.body?.id
          });
        }
      }
    });

    // GET / — server->client event stream (SSE under the hood)
    app.get('/', async (req: Request, res: ExpressResponse) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      if (!sessionId || !sessions.has(sessionId)) {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
          id: (req as any)?.body?.id
        });
        return;
      }
      try {
        const { transport } = sessions.get(sessionId)!;
        await transport.handleRequest(req, res);
      } catch (err) {
        console.error(`[${sessionId}] Error handling HTTP GET /:`, err);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: (req as any)?.body?.id
          });
        }
      }
    });

    // DELETE / — session termination
    app.delete('/', async (req: Request, res: ExpressResponse) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;
      if (!sessionId || !sessions.has(sessionId)) {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
          id: (req as any)?.body?.id
        });
        return;
      }
      try {
        const { transport } = sessions.get(sessionId)!;
        await transport.handleRequest(req, res);
      } catch (err) {
        console.error(`[${sessionId}] Error handling HTTP DELETE /:`, err);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Error handling session termination' },
            id: (req as any)?.body?.id
          });
        }
      }
    });

    app.listen(config.port, () => {
      console.log(`Listening on port ${config.port} (http) [storage=${config.storage}]`);
    });

    return; // do not fall through to SSE
  }

  // SSE
  const app = express();
  interface ServerSession {
    memoryKey: string;
    server: McpServer;
    transport: SSEServerTransport;
    sessionId: string;
  }
  let sessions: ServerSession[] = [];

  app.use((req, res, next) => {
    if (req.path === '/message') return next();
    express.json()(req, res, next);
  });

  app.get('/', async (req: Request, res: ExpressResponse) => {
    let memoryKey: string;
    if ((argv.storage as string) === 'memory-single') {
      memoryKey = "single";
    } else {
      const headerVal = req.headers[(argv.storageHeaderKey as string).toLowerCase()];
      if (typeof headerVal !== 'string' || !headerVal.trim()) {
        res.status(400).json({ error: `Missing or invalid "${argv.storageHeaderKey}" header` });
        return;
      }
      memoryKey = headerVal.trim();
    }
    const server = createMcpServer(memoryKey, config, toolsPrefix);
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

  app.listen(argv.port, () => {
    console.log(`Listening on port ${argv.port} (sse) [storage=${config.storage}]`);
  });
}

main().catch((err: any) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
