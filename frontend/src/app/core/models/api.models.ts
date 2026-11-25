export type Role = 'VIEWER' | 'OPERATOR' | 'MANAGER' | 'ADMIN';

export type Permission =
  | 'SECRET_LIST'
  | 'SECRET_REVEAL'
  | 'SECRET_WRITE'
  | 'SECRET_DELETE_RECOVER';

export type SyncStatus = 'IDLE' | 'LOADING' | 'COMPLETE' | 'PARTIAL_ERROR' | 'ERROR';

export type OperationState = 'PENDING' | 'IN_PROGRESS' | 'SUCCEEDED' | 'FAILED';

export type OperationType = 'SOFT_DELETE' | 'RECOVER';

export type AppProfile = 'local' | 'server';

export type AuthMode = 'BOOTSTRAP_TOKEN' | 'OIDC';

export type VaultSource = 'ARM_DISCOVERY' | 'STATIC_CONFIG';

export interface AuthStatusResponse {
  authenticated: boolean;
  subject?: string | null;
  displayName?: string | null;
  profile: AppProfile;
  authMode?: AuthMode;
  oidcLoginUrl?: string | null;
  deleteEnabled: boolean;
  idleTimeoutSeconds?: number;
  permissionsByVault: Record<string, Permission[]>;
}

export interface BootstrapLoginRequest {
  token: string;
}

export interface SubscriptionDto {
  subscriptionId: string;
  displayName: string;
  state?: string | null;
}

export interface VaultDto {
  id: string;
  name: string;
  subscriptionId?: string | null;
  resourceGroup?: string | null;
  location?: string | null;
  vaultUri: string;
  environment: string;
  production?: boolean;
  source: VaultSource;
  permissions: Permission[];
}

export interface SecretMetadataDto {
  name: string;
  version?: string | null;
  enabled: boolean;
  createdOn?: string | null;
  updatedOn?: string | null;
  expiresOn?: string | null;
  notBefore?: string | null;
  contentType?: string | null;
  tags?: Record<string, string>;
  managed?: boolean;
}

export interface SecretListSnapshotResponse {
  vaultId: string;
  status: SyncStatus;
  generationId: number;
  loadedCount: number;
  pagesLoaded: number;
  stale: boolean;
  lastSuccessfulSyncAt?: string | null;
  lastAttemptAt?: string | null;
  errorCode?: string | null;
  errorMessage?: string | null;
  items: SecretMetadataDto[];
}

export interface RevealSecretRequest {
  version?: string | null;
}

export interface SecretValueResponse {
  name: string;
  version?: string | null;
  value: string;
  contentType?: string | null;
  updatedOn?: string | null;
}

export interface CreateSecretRequest {
  name: string;
  value: string;
  enabled?: boolean;
  contentType?: string | null;
  expiresOn?: string | null;
  notBefore?: string | null;
  tags?: Record<string, string>;
}

export interface UpdateSecretRequest {
  value: string;
  expectedLatestVersion?: string | null;
  preserveMetadata?: boolean;
  enabled?: boolean | null;
  contentType?: string | null;
  expiresOn?: string | null;
  notBefore?: string | null;
  tags?: Record<string, string> | null;
}

export interface UpdateSecretPropertiesRequest {
  version?: string | null;
  enabled?: boolean | null;
  contentType?: string | null;
  expiresOn?: string | null;
  notBefore?: string | null;
  clearExpiresOn?: boolean;
  clearNotBefore?: boolean;
  tags?: Record<string, string> | null;
}

export interface SecretVersionDto {
  version: string;
  enabled: boolean;
  createdOn?: string | null;
  updatedOn?: string | null;
  expiresOn?: string | null;
  notBefore?: string | null;
  contentType?: string | null;
  tags?: Record<string, string>;
  latest?: boolean;
}

export interface DeleteSecretRequest {
  confirmSecretName: string;
}

export interface DeletedSecretDto {
  name: string;
  deletedOn?: string | null;
  scheduledPurgeDate?: string | null;
  recoveryId?: string | null;
  enabled?: boolean | null;
  contentType?: string | null;
  tags?: Record<string, string>;
}

export interface OperationStatusResponse {
  operationId: string;
  vaultId: string;
  secretName: string;
  operationType: OperationType;
  state: OperationState;
  createdAt: string;
  updatedAt: string;
  errorCode?: string | null;
  errorMessage?: string | null;
}

export interface ProblemDetail {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance?: string;
  errorCode: string;
  correlationId: string;
  retryAfterSeconds?: number | null;
  fieldErrors?: Record<string, string>;
}
