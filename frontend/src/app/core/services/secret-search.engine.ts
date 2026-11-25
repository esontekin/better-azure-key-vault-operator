import { SecretMetadataDto } from '../models/api.models';

export type SearchMatchMode = 'contains' | 'prefix' | 'exact';
export type StatusFilter = 'all' | 'enabled' | 'disabled';
export type ExpirationFilter = 'all' | 'expiring_soon' | 'expired' | 'no_expiry' | 'active';
export type SortField = 'name' | 'updatedOn' | 'expiresOn';
export type SortDirection = 'asc' | 'desc';

export interface SecretSearchCriteria {
  query: string;
  matchMode: SearchMatchMode;
  status: StatusFilter;
  expiration: ExpirationFilter;
  tagFilter: string;
  sortBy: SortField;
  sortDir: SortDirection;
}

export const DEFAULT_SEARCH_CRITERIA: SecretSearchCriteria = {
  query: '',
  matchMode: 'contains',
  status: 'all',
  expiration: 'all',
  tagFilter: '',
  sortBy: 'name',
  sortDir: 'asc',
};

const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

export interface IndexedSecret {
  readonly item: SecretMetadataDto;
  readonly lowerName: string;
  readonly lowerContentType: string;
  readonly lowerTagsBlob: string;
  readonly lowerTagKeys: readonly string[];
  readonly lowerTagMap: ReadonlyMap<string, string>;
  readonly updatedMs: number;
  readonly expiresMs: number;
  readonly hasExpiry: boolean;
}

export class SecretSearchIndex {
  private readonly entries: readonly IndexedSecret[];

  constructor(items: readonly SecretMetadataDto[]) {
    const built = new Array<IndexedSecret>(items.length);
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const lowerName = item.name.toLowerCase();
      const lowerContentType = item.contentType ? item.contentType.toLowerCase() : '';
      const tagMap = new Map<string, string>();
      const tagKeys: string[] = [];
      let tagsBlob = '';

      if (item.tags) {
        const keys = Object.keys(item.tags);
        if (keys.length > 0) {
          const parts: string[] = [];
          for (let j = 0; j < keys.length; j++) {
            const rawKey = keys[j];
            const rawVal = item.tags[rawKey] ?? '';
            const lk = rawKey.toLowerCase();
            const lv = rawVal.toLowerCase();
            tagMap.set(lk, lv);
            tagKeys.push(lk);
            parts.push(`${lk}=${lv}`);
          }
          tagsBlob = parts.join(' ');
        }
      }

      const updatedMs = item.updatedOn ? Date.parse(item.updatedOn) || 0 : 0;
      const parsedExp = item.expiresOn ? Date.parse(item.expiresOn) : Number.NaN;
      const hasExpiry = !Number.isNaN(parsedExp);
      const expiresMs = hasExpiry ? parsedExp : Number.POSITIVE_INFINITY;

      built[i] = {
        item,
        lowerName,
        lowerContentType,
        lowerTagsBlob: tagsBlob,
        lowerTagKeys: tagKeys,
        lowerTagMap: tagMap,
        updatedMs,
        expiresMs,
        hasExpiry,
      };
    }
    this.entries = built;
  }

  get size(): number {
    return this.entries.length;
  }

  search(criteria: SecretSearchCriteria, nowMs: number = Date.now()): SecretMetadataDto[] {
    const trimmedQuery = criteria.query.trim().toLowerCase();
    const tokens = trimmedQuery.length > 0 ? trimmedQuery.split(/\s+/) : [];
    const matchMode = criteria.matchMode;
    const status = criteria.status;
    const expiration = criteria.expiration;

    const rawTagFilter = criteria.tagFilter.trim().toLowerCase();
    let tagKeyFilter = '';
    let tagValFilter: string | null = null;
    if (rawTagFilter.length > 0) {
      const eqIdx = rawTagFilter.indexOf('=');
      if (eqIdx >= 0) {
        tagKeyFilter = rawTagFilter.slice(0, eqIdx).trim();
        tagValFilter = rawTagFilter.slice(eqIdx + 1).trim();
      } else {
        tagKeyFilter = rawTagFilter;
      }
    }

    const soonThreshold = nowMs + THIRTY_DAYS_MS;
    const matched: IndexedSecret[] = [];
    const entries = this.entries;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      if (status === 'enabled' && !entry.item.enabled) {
        continue;
      }
      if (status === 'disabled' && entry.item.enabled) {
        continue;
      }

      if (expiration !== 'all') {
        if (expiration === 'no_expiry' && entry.hasExpiry) {
          continue;
        }
        if (expiration === 'expired' && (!entry.hasExpiry || entry.expiresMs > nowMs)) {
          continue;
        }
        if (
          expiration === 'expiring_soon' &&
          (!entry.hasExpiry || entry.expiresMs <= nowMs || entry.expiresMs > soonThreshold)
        ) {
          continue;
        }
        if (expiration === 'active' && entry.hasExpiry && entry.expiresMs <= nowMs) {
          continue;
        }
      }

      if (tagKeyFilter.length > 0) {
        if (!matchesTagFilter(entry, tagKeyFilter, tagValFilter)) {
          continue;
        }
      }

      if (tokens.length > 0) {
        if (!matchesQuery(entry, trimmedQuery, tokens, matchMode)) {
          continue;
        }
      }

      matched.push(entry);
    }

    const dir = criteria.sortDir === 'asc' ? 1 : -1;
    const sortBy = criteria.sortBy;

    matched.sort((a, b) => {
      let cmp = 0;
      if (sortBy === 'name') {
        cmp = a.lowerName < b.lowerName ? -1 : a.lowerName > b.lowerName ? 1 : 0;
      } else if (sortBy === 'updatedOn') {
        cmp = a.updatedMs - b.updatedMs;
        if (cmp === 0) {
          cmp = a.lowerName < b.lowerName ? -1 : a.lowerName > b.lowerName ? 1 : 0;
        }
      } else {
        const aExp = a.hasExpiry ? a.expiresMs : (dir === 1 ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY);
        const bExp = b.hasExpiry ? b.expiresMs : (dir === 1 ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY);
        cmp = aExp - bExp;
        if (cmp === 0) {
          cmp = a.lowerName < b.lowerName ? -1 : a.lowerName > b.lowerName ? 1 : 0;
        }
      }
      return cmp * dir;
    });

    const result = new Array<SecretMetadataDto>(matched.length);
    for (let i = 0; i < matched.length; i++) {
      result[i] = matched[i].item;
    }
    return result;
  }
}

function matchesTagFilter(
  entry: IndexedSecret,
  keyFilter: string,
  valFilter: string | null
): boolean {
  if (entry.lowerTagKeys.length === 0) {
    return false;
  }
  if (valFilter !== null) {
    const exactVal = entry.lowerTagMap.get(keyFilter);
    if (exactVal !== undefined) {
      return valFilter.length === 0 || exactVal.includes(valFilter);
    }
    for (let i = 0; i < entry.lowerTagKeys.length; i++) {
      const k = entry.lowerTagKeys[i];
      if (k.includes(keyFilter)) {
        const v = entry.lowerTagMap.get(k) ?? '';
        if (valFilter.length === 0 || v.includes(valFilter)) {
          return true;
        }
      }
    }
    return false;
  }

  if (entry.lowerTagMap.has(keyFilter)) {
    return true;
  }
  for (let i = 0; i < entry.lowerTagKeys.length; i++) {
    if (entry.lowerTagKeys[i].includes(keyFilter)) {
      return true;
    }
  }
  return false;
}

function matchesQuery(
  entry: IndexedSecret,
  trimmedQuery: string,
  tokens: readonly string[],
  matchMode: SearchMatchMode
): boolean {
  if (matchMode === 'exact') {
    return entry.lowerName === trimmedQuery;
  }

  if (matchMode === 'prefix') {
    if (!entry.lowerName.startsWith(tokens[0])) {
      return false;
    }
    for (let t = 1; t < tokens.length; t++) {
      const tok = tokens[t];
      if (
        !entry.lowerName.includes(tok) &&
        !entry.lowerContentType.includes(tok) &&
        !entry.lowerTagsBlob.includes(tok)
      ) {
        return false;
      }
    }
    return true;
  }

  for (let t = 0; t < tokens.length; t++) {
    const tok = tokens[t];
    if (
      !entry.lowerName.includes(tok) &&
      !entry.lowerContentType.includes(tok) &&
      !entry.lowerTagsBlob.includes(tok)
    ) {
      return false;
    }
  }
  return true;
}
