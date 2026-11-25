import { Injectable, computed, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { AuthStatusResponse, Permission, ProblemDetail } from '../models/api.models';
import { ApiService } from './api.service';
import { extractProblemDetail, isAppAuthError } from '../utils/secret-validation.util';

@Injectable({ providedIn: 'root' })
export class AuthStore {
  private readonly api = inject(ApiService);

  readonly status = signal<AuthStatusResponse | null>(null);
  readonly loading = signal<boolean>(true);
  readonly submitting = signal<boolean>(false);
  readonly error = signal<ProblemDetail | null>(null);

  readonly authenticated = computed<boolean>(() => this.status()?.authenticated === true);
  readonly profile = computed(() => this.status()?.profile ?? 'local');
  readonly authMode = computed(() => this.status()?.authMode ?? (this.profile() === 'server' ? 'OIDC' : 'BOOTSTRAP_TOKEN'));
  readonly deleteEnabled = computed<boolean>(() => this.status()?.deleteEnabled === true);
  readonly subject = computed<string>(() => this.status()?.displayName || this.status()?.subject || '');

  async loadStatus(): Promise<AuthStatusResponse | null> {
    this.loading.set(true);
    this.error.set(null);
    try {
      const response = await firstValueFrom(this.api.getAuthStatus());
      this.status.set(response);
      return response;
    } catch (err) {
      this.error.set(extractProblemDetail(err));
      return null;
    } finally {
      this.loading.set(false);
    }
  }

  async loginWithBootstrapToken(token: string): Promise<boolean> {
    this.submitting.set(true);
    this.error.set(null);
    try {
      const response = await firstValueFrom(this.api.localBootstrapLogin({ token }));
      this.status.set(response);
      return response.authenticated;
    } catch (err) {
      this.error.set(extractProblemDetail(err));
      return false;
    } finally {
      this.submitting.set(false);
    }
  }

  async logout(): Promise<void> {
    this.submitting.set(true);
    this.error.set(null);
    try {
      await firstValueFrom(this.api.logout());
    } catch {
      // Even if session already expired, reload clean auth status
    } finally {
      this.submitting.set(false);
      await this.loadStatus();
    }
  }

  handleApiError(problem: ProblemDetail): void {
    if (isAppAuthError(problem)) {
      const current = this.status();
      if (current) {
        this.status.set({
          ...current,
          authenticated: false,
          subject: null,
          displayName: null,
          permissionsByVault: {},
        });
      }
      this.error.set(problem);
    }
  }

  hasPermission(
    vaultId: string | null | undefined,
    permission: Permission,
    vaultPermissions?: readonly Permission[]
  ): boolean {
    if (!this.authenticated() || !vaultId) {
      return false;
    }
    if (vaultPermissions && vaultPermissions.includes(permission)) {
      return true;
    }
    const map = this.status()?.permissionsByVault;
    const perms = map ? map[vaultId] : undefined;
    return Array.isArray(perms) && perms.includes(permission);
  }

  canDelete(vaultId: string | null | undefined, vaultPermissions?: readonly Permission[]): boolean {
    return this.deleteEnabled() && this.hasPermission(vaultId, 'SECRET_DELETE_RECOVER', vaultPermissions);
  }

  clearError(): void {
    this.error.set(null);
  }
}
