/**
 * OIDC Session Registry
 *
 * Server-side session tracking for back-channel logout support.
 * Uses Redis for distributed session management across instances.
 *
 * This registry enables the application to:
 * - Track active sessions for back-channel logout
 * - Invalidate specific sessions (by session ID)
 * - Invalidate all sessions for a user (by subject)
 * - Detect and prevent replay attacks (JTI cache)
 *
 * @see https://openid.net/specs/openid-connect-backchannel-1_0.html
 */

import Redis from 'ioredis';
import type { SessionRegistryStorage, SessionRegistryEntry } from './types';
import { SESSION_REGISTRY } from './constants';

/**
 * Redis session registry implementation
 *
 * Stores session data and JTI cache in Redis for back-channel logout.
 * Works in both development and production.
 *
 * Redis Keys Structure:
 * - `{prefix}:s:{sid}` - Session data (hash)
 * - `{prefix}:s:{sid}:invalidated` - Session invalidation flag
 * - `{prefix}:jti:{jti}` - JTI cache (string)
 * - `{prefix}:sub:{sub}` - User's session set (set)
 *
 * Requires: REDIS_URL environment variable
 */
export class RedisSessionRegistry implements SessionRegistryStorage {
  private redis: Redis;
  private prefix: string;

  constructor(redisUrl: string, prefix: string = 'oidc_session') {
    this.redis = new Redis(redisUrl);
    this.prefix = prefix;
  }

  /**
   * Generate the Redis key for a session entry
   */
  private sessionKey(sid: string): string {
    return `${this.prefix}:s:${sid}`;
  }

  /**
   * Generate the Redis key for a JTI entry
   */
  private jtiKey(jti: string): string {
    return `${this.prefix}:jti:${jti}`;
  }

  /**
   * Generate the Redis key for a user's session set
   */
  private subKey(sub: string): string {
    return `${this.prefix}:sub:${sub}`;
  }

  /**
   * Register a new session in the registry.
   *
   * @param entry - The session entry to register
   */
  async register(entry: SessionRegistryEntry): Promise<void> {
    const key = this.sessionKey(entry.sid);

    // Store session data as a hash
    await this.redis.hset(key, {
      sub: entry.sub,
      provider: entry.provider,
      createdAt: entry.createdAt.toString(),
      expiresAt: entry.expiresAt.toString(),
    });

    // Set expiration to match session expiry (Unix timestamp)
    await this.redis.expireat(key, Math.floor(entry.expiresAt / 1000));

    // Add to user's session set for global logout
    await this.redis.sadd(this.subKey(entry.sub), entry.sid);

    // Set expiration on the user's session set (same as session)
    await this.redis.expireat(
      this.subKey(entry.sub),
      Math.floor(entry.expiresAt / 1000)
    );
  }

  /**
   * Invalidate a specific session by session ID.
   *
   * @param sid - The session ID to invalidate
   * @returns Number of sessions invalidated (0 or 1)
   */
  async invalidateBySid(sid: string): Promise<number> {
    const key = this.sessionKey(sid);
    const exists = await this.redis.exists(key);

    if (exists) {
      // Mark as invalidated by setting a flag with TTL
      await this.redis.set(
        `${key}:invalidated`,
        '1',
        'EX',
        Math.floor(SESSION_REGISTRY.INVALIDATED_SESSION_TTL / 1000)
      );
      return 1;
    }

    return 0;
  }

  /**
   * Invalidate all sessions for a subject (user).
   *
   * @param sub - The subject (user ID)
   * @param provider - Optional provider filter
   * @returns Number of sessions invalidated
   */
  async invalidateBySub(sub: string, provider?: string): Promise<number> {
    const sessionIds = await this.redis.smembers(this.subKey(sub));
    let count = 0;

    for (const sid of sessionIds) {
      // Check provider match if specified
      const sessionData = await this.redis.hgetall(this.sessionKey(sid));

      if (Object.keys(sessionData).length === 0) {
        // Session doesn't exist anymore, clean up from set
        await this.redis.srem(this.subKey(sub), sid);
        continue;
      }

      if (provider && sessionData.provider !== provider) {
        continue;
      }

      await this.redis.set(
        `${this.sessionKey(sid)}:invalidated`,
        '1',
        'EX',
        Math.floor(SESSION_REGISTRY.INVALIDATED_SESSION_TTL / 1000)
      );
      count++;
    }

    return count;
  }

  /**
   * Check if a session is valid (not invalidated).
   *
   * @param sid - The session ID to check
   * @returns true if the session is valid, false otherwise
   */
  async isValid(sid: string): Promise<boolean> {
    const key = this.sessionKey(sid);
    const exists = await this.redis.exists(key);
    const invalidated = await this.redis.exists(`${key}:invalidated`);

    return exists === 1 && invalidated === 0;
  }

  /**
   * Clean up expired entries.
   *
   * Redis handles expiration automatically via TTL, so this is a no-op.
   *
   * @returns 0 (no cleanup needed)
   */
  async cleanup(): Promise<number> {
    // Redis handles expiration automatically via TTL
    return 0;
  }

  /**
   * Check if a JTI (JWT ID) has been used (replay protection).
   *
   * @param jti - The JTI to check
   * @returns true if the JTI has been used, false otherwise
   */
  async isJtiUsed(jti: string): Promise<boolean> {
    return (await this.redis.exists(this.jtiKey(jti))) === 1;
  }

  /**
   * Mark a JTI as used to prevent replay attacks.
   *
   * @param jti - The JTI to mark as used
   * @param expiresAt - Expiration timestamp (ms)
   */
  async markJtiUsed(jti: string, expiresAt: number): Promise<void> {
    const ttl = Math.floor((expiresAt - Date.now()) / 1000);
    await this.redis.set(
      this.jtiKey(jti),
      '1',
      'EX',
      Math.max(ttl, 1)
    );
  }

  /**
   * Close the Redis connection.
   */
  async close(): Promise<void> {
    await this.redis.quit();
  }
}

// Singleton instance - requires REDIS_URL
let _registry: RedisSessionRegistry | null = null;
let _initAttempted = false;
let _initError: Error | null = null;

/**
 * Get the singleton session registry instance.
 *
 * @returns The session registry instance
 * @throws {Error} If REDIS_URL is not set and registry is accessed
 */
export function getSessionRegistry(): RedisSessionRegistry {
  if (!_registry && !_initAttempted) {
    const redisUrl = process.env.REDIS_URL;
    if (!redisUrl) {
      _initAttempted = true;
      _initError = new Error(
        'REDIS_URL is required for session registry. ' +
          'Please ensure Redis is running and REDIS_URL is set.'
      );
      throw _initError;
    }
    _registry = new RedisSessionRegistry(redisUrl);
    _initAttempted = true;
  }

  if (_initError) {
    throw _initError;
  }

  return _registry!;
}

/**
 * Check if the session registry is available (REDIS_URL is set).
 *
 * @returns true if the registry can be initialized
 */
export function isSessionRegistryAvailable(): boolean {
  if (_registry) {
    return true;
  }
  if (_initAttempted) {
    return false;
  }
  return typeof process.env.REDIS_URL === 'string' && process.env.REDIS_URL.length > 0;
}

/**
 * Get the session registry instance if available.
 *
 * Unlike getSessionRegistry(), this returns null instead of throwing
 * if REDIS_URL is not set.
 *
 * @returns The session registry instance or null if not available
 */
export function getSessionRegistrySafe(): RedisSessionRegistry | null {
  if (!isSessionRegistryAvailable()) {
    return null;
  }
  try {
    return getSessionRegistry();
  } catch {
    return null;
  }
}

/**
 * Generate a cryptographically secure session ID.
 *
 * Uses 16 random bytes (128 bits of entropy) encoded as hex.
 *
 * @returns A 32-character hex string
 */
export function generateSessionId(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(16)))
    .toString('hex');
}

// Re-export types for convenience
export type { SessionRegistryEntry, SessionRegistryStorage };
