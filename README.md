# Facebook MCP Server

An MCP server that authenticates with Facebook and provides tools to list pages and post to a page.

## Token Handling

- User login returns a short‑lived user token (~1–2 hours). The server now exchanges it for a long‑lived user token (~60 days) using `grant_type=fb_exchange_token`.
- The long‑lived user token is stored under `accessToken` along with metadata:
  - `accessTokenType`
  - `accessTokenExpiresAt` (epoch ms)
- Backward compatibility: if an existing stored token has no `accessTokenExpiresAt`, the server attempts to upgrade it in place the next time it’s used.
- Page operations use Page access tokens retrieved from `/me/accounts`. These are cached under `pages` and are typically non‑expiring (but can be revoked by user/account changes). If a Page token appears invalid, the server refreshes the Page token cache and retries once.

## Storage

The server supports in‑memory and Upstash Redis (REST) storage. When using Upstash, tokens are saved as JSON blobs under the configured key prefix and your per‑client `memoryKey`.

## OAuth Scopes

The default scopes requested are:

```
public_profile,pages_show_list,pages_manage_posts,pages_read_engagement
```

These allow listing managed Pages and publishing posts to them.

## MCP Tools

- `auth_url`: Returns the Facebook Login URL.
- `exchange_auth_code`: Exchanges an OAuth code and upgrades to a long‑lived user token.
- `list_pages`: Lists Pages (and refreshes Page tokens).
- `create_page_post`: Publishes to a Page, preferring its Page token and retrying once on token errors.
- `read_page_posts`: Reads posts for a Page using its Page token.

## Notes

- There is no standard OAuth refresh_token for Facebook Login. The long‑lived user token can be re‑extended by calling the same exchange flow. This server attempts extensions when the token is within 7 days of expiry.
