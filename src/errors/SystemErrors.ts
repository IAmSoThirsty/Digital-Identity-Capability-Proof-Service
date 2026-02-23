/**
 * Production-grade error handling system
 * Provides typed errors, prevents information leakage, and supports error recovery
 */

/**
 * Base error class for all system errors
 */
export abstract class SystemError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly isOperational: boolean;
  public readonly timestamp: number;
  public readonly context?: Record<string, any>;

  constructor(
    message: string,
    code: string,
    statusCode: number,
    isOperational: boolean = true,
    context?: Record<string, any>
  ) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.timestamp = Date.now();
    this.context = context;

    Object.setPrototypeOf(this, new.target.prototype);
    Error.captureStackTrace(this, this.constructor);
  }

  /**
   * Get safe error message for external consumption
   * Prevents information leakage
   */
  public getSafeMessage(): string {
    return this.isOperational ? this.message : 'An internal error occurred';
  }

  /**
   * Get error details for logging
   */
  public getDetails(): ErrorDetails {
    return {
      code: this.code,
      message: this.message,
      statusCode: this.statusCode,
      timestamp: this.timestamp,
      context: this.context,
      stack: this.stack
    };
  }
}

/**
 * Validation errors (400)
 */
export class ValidationError extends SystemError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'VALIDATION_ERROR', 400, true, context);
    this.name = 'ValidationError';
  }
}

/**
 * Authentication errors (401)
 */
export class AuthenticationError extends SystemError {
  constructor(message: string = 'Authentication required', context?: Record<string, any>) {
    super(message, 'AUTHENTICATION_ERROR', 401, true, context);
    this.name = 'AuthenticationError';
  }
}

/**
 * Authorization errors (403)
 */
export class AuthorizationError extends SystemError {
  constructor(message: string = 'Access denied', context?: Record<string, any>) {
    super(message, 'AUTHORIZATION_ERROR', 403, true, context);
    this.name = 'AuthorizationError';
  }
}

/**
 * Not found errors (404)
 */
export class NotFoundError extends SystemError {
  constructor(resource: string, id: string) {
    super(
      `${resource} not found: ${id}`,
      'NOT_FOUND',
      404,
      true,
      { resource, id }
    );
    this.name = 'NotFoundError';
  }
}

/**
 * Conflict errors (409)
 */
export class ConflictError extends SystemError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'CONFLICT', 409, true, context);
    this.name = 'ConflictError';
  }
}

/**
 * Rate limit errors (429)
 */
export class RateLimitError extends SystemError {
  public readonly retryAfter: number;

  constructor(retryAfter: number, context?: Record<string, any>) {
    super(
      `Rate limit exceeded. Retry after ${retryAfter} seconds`,
      'RATE_LIMIT_EXCEEDED',
      429,
      true,
      { ...context, retryAfter }
    );
    this.retryAfter = retryAfter;
    this.name = 'RateLimitError';
  }
}

/**
 * Cryptographic operation errors (500)
 */
export class CryptographicError extends SystemError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'CRYPTOGRAPHIC_ERROR', 500, false, context);
    this.name = 'CryptographicError';
  }
}

/**
 * Proof generation errors (500)
 */
export class ProofGenerationError extends SystemError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'PROOF_GENERATION_ERROR', 500, true, context);
    this.name = 'ProofGenerationError';
  }
}

/**
 * Proof verification errors (400)
 */
export class ProofVerificationError extends SystemError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'PROOF_VERIFICATION_ERROR', 400, true, context);
    this.name = 'ProofVerificationError';
  }
}

/**
 * Credential errors (400)
 */
export class CredentialError extends SystemError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'CREDENTIAL_ERROR', 400, true, context);
    this.name = 'CredentialError';
  }
}

/**
 * Revocation errors (400)
 */
export class RevocationError extends SystemError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'REVOCATION_ERROR', 400, true, context);
    this.name = 'RevocationError';
  }
}

/**
 * Configuration errors (500)
 */
export class ConfigurationError extends SystemError {
  constructor(message: string, context?: Record<string, any>) {
    super(message, 'CONFIGURATION_ERROR', 500, false, context);
    this.name = 'ConfigurationError';
  }
}

/**
 * Timeout errors (504)
 */
export class TimeoutError extends SystemError {
  constructor(operation: string, timeoutMs: number) {
    super(
      `Operation timed out: ${operation}`,
      'TIMEOUT',
      504,
      true,
      { operation, timeoutMs }
    );
    this.name = 'TimeoutError';
  }
}

/**
 * Circuit breaker errors (503)
 */
export class CircuitBreakerError extends SystemError {
  constructor(service: string) {
    super(
      `Circuit breaker open for service: ${service}`,
      'CIRCUIT_BREAKER_OPEN',
      503,
      true,
      { service }
    );
    this.name = 'CircuitBreakerError';
  }
}

/**
 * Error details for logging
 */
export interface ErrorDetails {
  code: string;
  message: string;
  statusCode: number;
  timestamp: number;
  context?: Record<string, any>;
  stack?: string;
}

/**
 * Error handler utility
 */
export class ErrorHandler {
  /**
   * Handle error and determine if it's safe to continue
   */
  static handleError(error: Error): { safe: boolean; message: string } {
    if (error instanceof SystemError) {
      return {
        safe: error.isOperational,
        message: error.getSafeMessage()
      };
    }

    // Unknown error - not safe
    return {
      safe: false,
      message: 'An unexpected error occurred'
    };
  }

  /**
   * Log error with appropriate level
   */
  static logError(error: Error, logger?: any): void {
    if (error instanceof SystemError) {
      const details = error.getDetails();

      if (error.statusCode >= 500) {
        console.error('[ERROR]', details);
      } else if (error.statusCode >= 400) {
        console.warn('[WARNING]', details);
      } else {
        console.info('[INFO]', details);
      }
    } else {
      console.error('[CRITICAL]', {
        message: error.message,
        stack: error.stack,
        timestamp: Date.now()
      });
    }
  }

  /**
   * Wrap async operation with error handling
   */
  static async withErrorHandling<T>(
    operation: () => Promise<T>,
    errorMessage: string
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof SystemError) {
        throw error;
      }

      throw new CryptographicError(
        errorMessage,
        { originalError: error instanceof Error ? error.message : String(error) }
      );
    }
  }

  /**
   * Wrap operation with timeout
   */
  static async withTimeout<T>(
    operation: () => Promise<T>,
    timeoutMs: number,
    operationName: string
  ): Promise<T> {
    return Promise.race([
      operation(),
      new Promise<T>((_, reject) =>
        setTimeout(() => reject(new TimeoutError(operationName, timeoutMs)), timeoutMs)
      )
    ]);
  }
}
