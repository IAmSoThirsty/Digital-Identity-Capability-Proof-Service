/**
 * Role-Based Access Control (RBAC) system
 * Implements fine-grained permissions for production security
 */
import { AuthorizationError as SystemAuthorizationError } from '../errors/SystemErrors';

export class AccessControl {
  private rolePermissions: Map<Role, Set<Permission>>;
  private userRoles: Map<string, Set<Role>>;
  private resourceOwners: Map<string, string>;

  constructor() {
    this.rolePermissions = new Map();
    this.userRoles = new Map();
    this.resourceOwners = new Map();
    this.initializeDefaultRoles();
  }

  /**
   * Initialize default role-permission mappings
   */
  private initializeDefaultRoles(): void {
    // System Administrator
    this.rolePermissions.set('SYSTEM_ADMIN', new Set([
      'IDENTITY_CREATE',
      'IDENTITY_READ',
      'IDENTITY_UPDATE',
      'IDENTITY_DELETE',
      'CREDENTIAL_ISSUE',
      'CREDENTIAL_READ',
      'CREDENTIAL_REVOKE',
      'PROOF_GENERATE',
      'PROOF_VERIFY',
      'AUDIT_READ',
      'AUDIT_EXPORT',
      'ROLE_ASSIGN',
      'ROLE_REVOKE',
      'SYSTEM_CONFIG'
    ]));

    // Issuer
    this.rolePermissions.set('ISSUER', new Set([
      'IDENTITY_READ',
      'CREDENTIAL_ISSUE',
      'CREDENTIAL_READ',
      'CREDENTIAL_REVOKE',
      'AUDIT_READ'
    ]));

    // Verifier
    this.rolePermissions.set('VERIFIER', new Set([
      'PROOF_VERIFY',
      'CREDENTIAL_READ',
      'AUDIT_READ'
    ]));

    // Identity Owner
    this.rolePermissions.set('IDENTITY_OWNER', new Set([
      'IDENTITY_READ_OWN',
      'IDENTITY_UPDATE_OWN',
      'CREDENTIAL_READ_OWN',
      'PROOF_GENERATE_OWN'
    ]));

    // Auditor
    this.rolePermissions.set('AUDITOR', new Set([
      'AUDIT_READ',
      'AUDIT_EXPORT',
      'CREDENTIAL_READ',
      'IDENTITY_READ'
    ]));

    // Public (unauthenticated)
    this.rolePermissions.set('PUBLIC', new Set([
      'PROOF_VERIFY'
    ]));
  }

  /**
   * Assign role to user
   */
  assignRole(userId: string, role: Role): void {
    if (!this.rolePermissions.has(role)) {
      throw new Error(`Invalid role: ${role}`);
    }

    if (!this.userRoles.has(userId)) {
      this.userRoles.set(userId, new Set());
    }

    this.userRoles.get(userId)!.add(role);
  }

  /**
   * Revoke role from user
   */
  revokeRole(userId: string, role: Role): void {
    const roles = this.userRoles.get(userId);
    if (roles) {
      roles.delete(role);
    }
  }

  /**
   * Get all roles for user
   */
  getUserRoles(userId: string): Role[] {
    return Array.from(this.userRoles.get(userId) || []);
  }

  /**
   * Check if user has permission
   */
  hasPermission(userId: string, permission: Permission, resourceId?: string): boolean {
    const roles = this.userRoles.get(userId) || new Set();

    // Check if any of the user's roles grant the permission
    for (const role of roles) {
      const permissions = this.rolePermissions.get(role) || new Set();

      // Check exact permission
      if (permissions.has(permission)) {
        // For "own" permissions, verify ownership
        if (permission.endsWith('_OWN') && resourceId) {
          return this.isResourceOwner(userId, resourceId);
        }
        return true;
      }
    }

    return false;
  }

  /**
   * Require permission (throws if not authorized)
   */
  requirePermission(userId: string, permission: Permission, resourceId?: string): void {
    if (!this.hasPermission(userId, permission, resourceId)) {
      throw new SystemAuthorizationError(
        `User ${userId} lacks permission: ${permission}`
      );
    }
  }

  /**
   * Check if user has any of the specified permissions
   */
  hasAnyPermission(userId: string, permissions: Permission[]): boolean {
    return permissions.some(perm => this.hasPermission(userId, perm));
  }

  /**
   * Check if user has all of the specified permissions
   */
  hasAllPermissions(userId: string, permissions: Permission[]): boolean {
    return permissions.every(perm => this.hasPermission(userId, perm));
  }

  /**
   * Set resource owner
   */
  setResourceOwner(resourceId: string, ownerId: string): void {
    this.resourceOwners.set(resourceId, ownerId);
  }

  /**
   * Check if user is resource owner
   */
  isResourceOwner(userId: string, resourceId: string): boolean {
    return this.resourceOwners.get(resourceId) === userId;
  }

  /**
   * Add custom permission to role
   */
  addPermissionToRole(role: Role, permission: Permission): void {
    if (!this.rolePermissions.has(role)) {
      this.rolePermissions.set(role, new Set());
    }
    this.rolePermissions.get(role)!.add(permission);
  }

  /**
   * Remove permission from role
   */
  removePermissionFromRole(role: Role, permission: Permission): void {
    const permissions = this.rolePermissions.get(role);
    if (permissions) {
      permissions.delete(permission);
    }
  }

  /**
   * Get all permissions for role
   */
  getRolePermissions(role: Role): Permission[] {
    return Array.from(this.rolePermissions.get(role) || []);
  }

  /**
   * Get effective permissions for user (union of all role permissions)
   */
  getUserPermissions(userId: string): Permission[] {
    const roles = this.userRoles.get(userId) || new Set();
    const permissions = new Set<Permission>();

    for (const role of roles) {
      const rolePerms = this.rolePermissions.get(role) || new Set();
      for (const perm of rolePerms) {
        permissions.add(perm);
      }
    }

    return Array.from(permissions);
  }

  /**
   * Check if user has role
   */
  hasRole(userId: string, role: Role): boolean {
    const roles = this.userRoles.get(userId);
    return roles ? roles.has(role) : false;
  }

  /**
   * Check if user has any of the specified roles
   */
  hasAnyRole(userId: string, roles: Role[]): boolean {
    return roles.some(role => this.hasRole(userId, role));
  }
}

/**
 * Authorization error (re-export from SystemErrors for convenience)
 */
export { AuthorizationError } from '../errors/SystemErrors';

/**
 * Available roles
 */
export type Role =
  | 'SYSTEM_ADMIN'
  | 'ISSUER'
  | 'VERIFIER'
  | 'IDENTITY_OWNER'
  | 'AUDITOR'
  | 'PUBLIC';

/**
 * Available permissions
 */
export type Permission =
  // Identity permissions
  | 'IDENTITY_CREATE'
  | 'IDENTITY_READ'
  | 'IDENTITY_READ_OWN'
  | 'IDENTITY_UPDATE'
  | 'IDENTITY_UPDATE_OWN'
  | 'IDENTITY_DELETE'

  // Credential permissions
  | 'CREDENTIAL_ISSUE'
  | 'CREDENTIAL_READ'
  | 'CREDENTIAL_READ_OWN'
  | 'CREDENTIAL_REVOKE'

  // Proof permissions
  | 'PROOF_GENERATE'
  | 'PROOF_GENERATE_OWN'
  | 'PROOF_VERIFY'

  // Audit permissions
  | 'AUDIT_READ'
  | 'AUDIT_EXPORT'

  // Role management permissions
  | 'ROLE_ASSIGN'
  | 'ROLE_REVOKE'

  // System permissions
  | 'SYSTEM_CONFIG';
