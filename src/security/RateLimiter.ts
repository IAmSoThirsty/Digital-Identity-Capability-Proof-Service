/**
 * Production-grade rate limiter with multiple strategies
 * Prevents DoS attacks and ensures fair resource usage
 */
export class RateLimiter {
  private tokenBuckets: Map<string, TokenBucket> = new Map();
  private slidingWindows: Map<string, SlidingWindow> = new Map();
  private requestCounts: Map<string, number> = new Map();

  /**
   * Check if request should be rate limited (token bucket algorithm)
   */
  async checkLimit(
    key: string,
    capacity: number,
    refillRate: number
  ): Promise<RateLimitResult> {
    let bucket = this.tokenBuckets.get(key);

    if (!bucket) {
      bucket = new TokenBucket(capacity, refillRate);
      this.tokenBuckets.set(key, bucket);
    }

    const allowed = bucket.consume(1);

    return {
      allowed,
      remaining: Math.floor(bucket.tokens),
      resetTime: bucket.getResetTime(),
      retryAfter: allowed ? undefined : bucket.getRetryAfter()
    };
  }

  /**
   * Check rate limit using sliding window algorithm
   */
  async checkSlidingWindow(
    key: string,
    limit: number,
    windowMs: number
  ): Promise<RateLimitResult> {
    let window = this.slidingWindows.get(key);

    if (!window) {
      window = new SlidingWindow(limit, windowMs);
      this.slidingWindows.set(key, window);
    }

    const allowed = window.addRequest();

    return {
      allowed,
      remaining: limit - window.getCount(),
      resetTime: window.getResetTime(),
      retryAfter: allowed ? undefined : window.getRetryAfter()
    };
  }

  /**
   * Get current request count for key
   */
  getRequestCount(key: string): number {
    return this.requestCounts.get(key) || 0;
  }

  /**
   * Reset rate limit for key
   */
  reset(key: string): void {
    this.tokenBuckets.delete(key);
    this.slidingWindows.delete(key);
    this.requestCounts.delete(key);
  }

  /**
   * Clear all rate limits
   */
  clearAll(): void {
    this.tokenBuckets.clear();
    this.slidingWindows.clear();
    this.requestCounts.clear();
  }

  /**
   * Cleanup expired entries
   */
  cleanup(): void {
    const now = Date.now();

    // Clean up expired sliding windows
    for (const [key, window] of this.slidingWindows.entries()) {
      if (now - window.lastReset > window.windowMs * 2) {
        this.slidingWindows.delete(key);
      }
    }
  }
}

/**
 * Token bucket implementation
 */
class TokenBucket {
  public tokens: number;
  private lastRefill: number;

  constructor(
    private capacity: number,
    private refillRate: number // tokens per second
  ) {
    this.tokens = capacity;
    this.lastRefill = Date.now();
  }

  /**
   * Try to consume tokens
   */
  consume(amount: number): boolean {
    this.refill();

    if (this.tokens >= amount) {
      this.tokens -= amount;
      return true;
    }

    return false;
  }

  /**
   * Refill tokens based on time elapsed
   */
  private refill(): void {
    const now = Date.now();
    const elapsedSeconds = (now - this.lastRefill) / 1000;
    const tokensToAdd = elapsedSeconds * this.refillRate;

    this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
    this.lastRefill = now;
  }

  /**
   * Get time until bucket is reset
   */
  getResetTime(): number {
    if (this.tokens >= this.capacity) {
      return Date.now();
    }

    const tokensNeeded = this.capacity - this.tokens;
    const secondsUntilFull = tokensNeeded / this.refillRate;

    return Date.now() + secondsUntilFull * 1000;
  }

  /**
   * Get retry-after time in seconds
   */
  getRetryAfter(): number {
    const tokensNeeded = 1 - this.tokens;
    if (tokensNeeded <= 0) {
      return 0;
    }

    return Math.ceil(tokensNeeded / this.refillRate);
  }
}

/**
 * Sliding window implementation
 */
class SlidingWindow {
  private requests: number[] = [];
  public lastReset: number;

  constructor(
    private limit: number,
    public windowMs: number
  ) {
    this.lastReset = Date.now();
  }

  /**
   * Add a request to the window
   */
  addRequest(): boolean {
    const now = Date.now();
    this.cleanup(now);

    if (this.requests.length < this.limit) {
      this.requests.push(now);
      return true;
    }

    return false;
  }

  /**
   * Get current request count
   */
  getCount(): number {
    this.cleanup(Date.now());
    return this.requests.length;
  }

  /**
   * Remove expired requests
   */
  private cleanup(now: number): void {
    const cutoff = now - this.windowMs;
    this.requests = this.requests.filter(time => time > cutoff);
  }

  /**
   * Get time until window resets
   */
  getResetTime(): number {
    if (this.requests.length === 0) {
      return Date.now();
    }

    return this.requests[0] + this.windowMs;
  }

  /**
   * Get retry-after time in seconds
   */
  getRetryAfter(): number {
    if (this.requests.length === 0) {
      return 0;
    }

    const oldest = this.requests[0];
    const resetTime = oldest + this.windowMs;
    const waitTime = resetTime - Date.now();

    return Math.ceil(waitTime / 1000);
  }
}

/**
 * Rate limit result
 */
export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
}

/**
 * Rate limit configuration
 */
export interface RateLimitConfig {
  // Per-identity limits
  identityCreate: { capacity: number; refillRate: number };
  credentialIssue: { capacity: number; refillRate: number };
  proofGenerate: { capacity: number; refillRate: number };
  proofVerify: { capacity: number; refillRate: number };

  // Global limits
  globalRequests: { limit: number; windowMs: number };
}

/**
 * Default rate limit configuration
 */
export const DEFAULT_RATE_LIMITS: RateLimitConfig = {
  identityCreate: {
    capacity: 10,
    refillRate: 1 / 60 // 1 per minute
  },
  credentialIssue: {
    capacity: 100,
    refillRate: 10 / 60 // 10 per minute
  },
  proofGenerate: {
    capacity: 50,
    refillRate: 5 / 60 // 5 per minute
  },
  proofVerify: {
    capacity: 1000,
    refillRate: 100 / 60 // 100 per minute
  },
  globalRequests: {
    limit: 10000,
    windowMs: 60000 // 10000 per minute
  }
};
