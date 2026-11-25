import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import {
  AuthStatusResponse,
  BootstrapLoginRequest,
  CreateSecretRequest,
  DeleteSecretRequest,
  DeletedSecretDto,
  OperationStatusResponse,
  RevealSecretRequest,
  SecretListSnapshotResponse,
  SecretMetadataDto,
  SecretValueResponse,
  SecretVersionDto,
  SubscriptionDto,
  UpdateSecretPropertiesRequest,
  UpdateSecretRequest,
  VaultDto,
} from '../models/api.models';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1';

  getAuthStatus(): Observable<AuthStatusResponse> {
    return this.http.get<AuthStatusResponse>(`${this.baseUrl}/auth/status`, {
      withCredentials: true,
    });
  }

  localBootstrapLogin(request: BootstrapLoginRequest): Observable<AuthStatusResponse> {
    return this.http.post<AuthStatusResponse>(`${this.baseUrl}/auth/bootstrap`, request, {
      withCredentials: true,
    });
  }

  logout(): Observable<void> {
    return this.http.post<void>(`${this.baseUrl}/auth/logout`, {}, {
      withCredentials: true,
    });
  }

  listSubscriptions(): Observable<SubscriptionDto[]> {
    return this.http.get<SubscriptionDto[]>(`${this.baseUrl}/subscriptions`, {
      withCredentials: true,
    });
  }

  listVaults(subscriptionId?: string | null): Observable<VaultDto[]> {
    let params = new HttpParams();
    if (subscriptionId) {
      params = params.set('subscriptionId', subscriptionId);
    }
    return this.http.get<VaultDto[]>(`${this.baseUrl}/vaults`, {
      params,
      withCredentials: true,
    });
  }

  getSecretsSnapshot(vaultId: string): Observable<SecretListSnapshotResponse> {
    return this.http.get<SecretListSnapshotResponse>(
      `${this.baseUrl}/vaults/${encodeURIComponent(vaultId)}/secrets`,
      { withCredentials: true }
    );
  }

  refreshVaultSecrets(vaultId: string): Observable<SecretListSnapshotResponse> {
    return this.http.post<SecretListSnapshotResponse>(
      `${this.baseUrl}/vaults/${encodeURIComponent(vaultId)}/refresh`,
      {},
      { withCredentials: true }
    );
  }

  createSecret(vaultId: string, request: CreateSecretRequest): Observable<SecretMetadataDto> {
    return this.http.post<SecretMetadataDto>(
      `${this.baseUrl}/vaults/${encodeURIComponent(vaultId)}/secrets`,
      request,
      { withCredentials: true }
    );
  }

  getSecretMetadata(vaultId: string, secretName: string): Observable<SecretMetadataDto> {
    return this.http.get<SecretMetadataDto>(
      `${this.baseUrl}/vaults/${encodeURIComponent(vaultId)}/secrets/${encodeURIComponent(secretName)}`,
      { withCredentials: true }
    );
  }

  revealSecret(
    vaultId: string,
    secretName: string,
    request?: RevealSecretRequest
  ): Observable<SecretValueResponse> {
    return this.http.post<SecretValueResponse>(
      `${this.baseUrl}/vaults/${encodeURIComponent(vaultId)}/secrets/${encodeURIComponent(secretName)}/reveal`,
      request ?? {},
      { withCredentials: true }
    );
  }

  updateSecretValue(
    vaultId: string,
    secretName: string,
    request: UpdateSecretRequest
  ): Observable<SecretMetadataDto> {
    return this.http.put<SecretMetadataDto>(
      `${this.baseUrl}/vaults/${encodeURIComponent(vaultId)}/secrets/${encodeURIComponent(secretName)}`,
      request,
      { withCredentials: true }
    );
  }

  updateSecretProperties(
    vaultId: string,
    secretName: string,
    request: UpdateSecretPropertiesRequest
  ): Observable<SecretMetadataDto> {
    return this.http.patch<SecretMetadataDto>(
      `${this.baseUrl}/vaults/${encodeURIComponent(vaultId)}/secrets/${encodeURIComponent(secretName)}/properties`,
      request,
      { withCredentials: true }
    );
  }

  listSecretVersions(vaultId: string, secretName: string): Observable<SecretVersionDto[]> {
    return this.http.get<SecretVersionDto[]>(
      `${this.baseUrl}/vaults/${encodeURIComponent(vaultId)}/secrets/${encodeURIComponent(secretName)}/versions`,
      { withCredentials: true }
    );
  }

  softDeleteSecret(
    vaultId: string,
    secretName: string,
    request: DeleteSecretRequest
  ): Observable<OperationStatusResponse> {
    return this.http.delete<OperationStatusResponse>(
      `${this.baseUrl}/vaults/${encodeURIComponent(vaultId)}/secrets/${encodeURIComponent(secretName)}`,
      {
        body: request,
        withCredentials: true,
      }
    );
  }

  listDeletedSecrets(vaultId: string): Observable<DeletedSecretDto[]> {
    return this.http.get<DeletedSecretDto[]>(
      `${this.baseUrl}/vaults/${encodeURIComponent(vaultId)}/deleted-secrets`,
      { withCredentials: true }
    );
  }

  recoverDeletedSecret(vaultId: string, secretName: string): Observable<OperationStatusResponse> {
    return this.http.post<OperationStatusResponse>(
      `${this.baseUrl}/vaults/${encodeURIComponent(vaultId)}/deleted-secrets/${encodeURIComponent(secretName)}/recover`,
      {},
      { withCredentials: true }
    );
  }

  getOperationStatus(operationId: string): Observable<OperationStatusResponse> {
    return this.http.get<OperationStatusResponse>(
      `${this.baseUrl}/operations/${encodeURIComponent(operationId)}`,
      { withCredentials: true }
    );
  }
}
