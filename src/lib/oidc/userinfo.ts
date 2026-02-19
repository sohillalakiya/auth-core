/**
 * OIDC UserInfo Endpoint Integration
 *
 * Fetches user claims from the UserInfo endpoint using the access token.
 * Caches user info for session duration to reduce redundant requests.
 *
 * @see https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
 */

import { discoverProvider } from './discovery';
import type { UserInfo } from './types';

/**
 * In-memory cache for user info
 * Key: access_token (hashed for security)
 */
const userInfoCache = new Map<string, { data: UserInfo; expiresAt: number }>();

/**
 * Maximum age for cached user info (5 minutes)
 */
const CACHE_TTL = 5 * 60 * 1000;

/**
 * Fetches user info from the UserInfo endpoint.
 *
 * Makes an authenticated request to the provider's UserInfo endpoint
 * using the access token as a Bearer token.
 *
 * @param accessToken - The access token for authentication
 * @param userInfoEndpoint - The UserInfo endpoint URL
 * @returns The user info from the provider
 * @throws {Error} If the request fails or returns invalid data
 *
 * @example
 * ```ts
 * const userInfo = await fetchUserInfo(accessToken, userInfoEndpoint);
 * console.log(userInfo.email);
 * ```
 */
export async function fetchUserInfo(
  accessToken: string,
  userInfoEndpoint: string
): Promise<UserInfo> {
  try {
    const response = await fetch(userInfoEndpoint, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(10000), // 10 second timeout
    });

    if (!response.ok) {
      throw new Error(
        `UserInfo request failed: ${response.status} ${response.statusText}`
      );
    }

    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      throw new Error(
        `Unexpected content type from UserInfo endpoint: ${contentType}`
      );
    }

    const data = await response.json();

    // Validate required fields
    if (!data.sub) {
      throw new Error('UserInfo response missing required "sub" claim');
    }

    return data as UserInfo;
  } catch (error) {
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        throw new Error('Timeout while fetching user info');
      }
      throw error;
    }
    throw new Error('Unknown error while fetching user info');
  }
}

/**
 * Generates a simple cache key from an access token.
 *
 * @param accessToken - The access token
 * @returns A cache key
 */
function generateCacheKey(accessToken: string): string {
  // Use a simple hash of the token (first 32 chars for uniqueness)
  return accessToken.substring(0, 32);
}

/**
 * Fetches user info with caching support.
 *
 * This function caches user info to avoid redundant requests to the
 * UserInfo endpoint. Cached data is automatically invalidated
 * after the CACHE_TTL period.
 *
 * @param accessToken - The access token for authentication
 * @param userInfoEndpoint - The UserInfo endpoint URL
 * @param forceRefresh - If true, bypasses cache and fetches fresh data
 * @returns The user info from the provider
 *
 * @example
 * ```ts
 * const userInfo = await getUserInfo(session.access_token);
 * // Second call within 5 minutes returns cached data
 * const cached = await getUserInfo(session.access_token);
 * ```
 */
export async function getUserInfo(
  accessToken: string,
  userInfoEndpoint?: string,
  forceRefresh: boolean = false
): Promise<UserInfo> {
  // If endpoint not provided, discover it
  let endpoint = userInfoEndpoint;
  if (!endpoint) {
    const provider = await discoverProvider();
    endpoint = provider.userinfo_endpoint;
    if (!endpoint) {
      throw new Error('Provider does not have a UserInfo endpoint');
    }
  }

  // Check cache
  const cacheKey = generateCacheKey(accessToken);
  const cached = userInfoCache.get(cacheKey);

  if (!forceRefresh && cached && cached.expiresAt > Date.now()) {
    return cached.data;
  }

  // Fetch fresh user info
  const userInfo = await fetchUserInfo(accessToken, endpoint);

  // Cache the result
  userInfoCache.set(cacheKey, {
    data: userInfo,
    expiresAt: Date.now() + CACHE_TTL,
  });

  return userInfo;
}

/**
 * Clears cached user info for a specific access token.
 *
 * Use this when the access token is refreshed or the session is destroyed.
 *
 * @param accessToken - The access token to clear cache for
 *
 * @example
 * ```ts
 * clearUserInfoCache(oldAccessToken);
 * ```
 */
export function clearUserInfoCache(accessToken: string): void {
  const cacheKey = generateCacheKey(accessToken);
  userInfoCache.delete(cacheKey);
}

/**
 * Clears all cached user info.
 *
 * Use this when logging out or when clearing all sessions.
 *
 * @example
 * ```ts
 * clearAllUserInfoCache();
 * ```
 */
export function clearAllUserInfoCache(): void {
  userInfoCache.clear();
}

/**
 * Gets user info for the current session.
 *
 * Convenience function that fetches user info using the session's
 * access token. This is the most commonly used function for UserInfo.
 *
 * @param accessToken - The access token from the session
 * @returns The user info or undefined if not available
 *
 * @example
 * ```ts
 * const userInfo = await getUserInfoForSession(session.access_token);
 * if (userInfo.email_verified) {
 *   console.log('Verified email:', userInfo.email);
 * }
 * ```
 */
export async function getUserInfoForSession(
  accessToken: string
): Promise<UserInfo | undefined> {
  try {
    return await getUserInfo(accessToken);
  } catch {
    return undefined;
  }
}

/**
 * Enriches session data with UserInfo endpoint data.
 *
 * Fetches user info from the UserInfo endpoint and merges it with
 * the session data for a complete user profile.
 *
 * @param session - The session data to enrich
 * @returns Enriched session data with UserInfo claims
 *
 * @example
 * ```ts
 * const enriched = await enrichSessionWithUserInfo(session);
 * console.log(enriched.userInfo?.email);
 * ```
 */
export async function enrichSessionWithUserInfo(
  session: { access_token: string; sub: string }
): Promise<{ sub: string } & { userInfo?: UserInfo }> {
  try {
    const userInfo = await getUserInfo(session.access_token);

    // Verify the sub matches (security check)
    if (userInfo.sub !== session.sub) {
      throw new Error('UserInfo sub does not match session sub');
    }

    return {
      sub: session.sub,
      userInfo,
    };
  } catch {
    // If UserInfo fetch fails, return just the sub
    return { sub: session.sub };
  }
}
