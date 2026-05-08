import { randomInt, createHash } from 'crypto';
import Redis from 'ioredis';
import { OTP_REDIS_PREFIX } from './constants';

const OTP_TTL_SECONDS = 300; // 5 minutes
const MAX_ATTEMPTS = 3;

interface OtpRecord {
  otpHash: string;
  attempts: number;
}

export type VerifyOtpResult = 'ok' | 'invalid' | 'expired' | 'locked';

let _redis: Redis | null = null;

function getRedis(): Redis {
  if (!_redis) {
    const url = process.env.REDIS_URL;
    if (!url) throw new Error('REDIS_URL is required');
    _redis = new Redis(url);
  }
  return _redis;
}

function otpKey(email: string): string {
  const encoded = Buffer.from(email.toLowerCase()).toString('base64url');
  return `${OTP_REDIS_PREFIX}:${encoded}`;
}

function hashOtp(otp: string, email: string): string {
  // Salt with email to prevent rainbow-table attacks on the 6-digit space
  return createHash('sha256')
    .update(`${otp}:${email.toLowerCase()}`)
    .digest('base64url');
}

export function generateOtp(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, '0');
}

export async function storeOtp(email: string, otp: string): Promise<void> {
  const record: OtpRecord = { otpHash: hashOtp(otp, email), attempts: 0 };
  await getRedis().set(otpKey(email), JSON.stringify(record), 'EX', OTP_TTL_SECONDS);
}

export async function verifyOtp(email: string, submitted: string): Promise<VerifyOtpResult> {
  const redis = getRedis();
  const key = otpKey(email);
  const raw = await redis.get(key);

  if (!raw) return 'expired';

  const record: OtpRecord = JSON.parse(raw);

  if (record.attempts >= MAX_ATTEMPTS) {
    await redis.del(key);
    return 'locked';
  }

  const submittedHash = hashOtp(submitted.trim(), email);

  if (record.otpHash !== submittedHash) {
    record.attempts += 1;
    if (record.attempts >= MAX_ATTEMPTS) {
      await redis.del(key);
      return 'locked';
    }
    // Preserve remaining TTL on failed attempt
    const ttl = await redis.ttl(key);
    await redis.set(key, JSON.stringify(record), 'EX', ttl > 0 ? ttl : OTP_TTL_SECONDS);
    return 'invalid';
  }

  await redis.del(key);
  return 'ok';
}
