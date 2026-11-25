import { Injectable, inject } from '@angular/core';
import { Observable, interval, of, switchMap, takeWhile, startWith, timeout } from 'rxjs';
import { OperationStatusResponse } from '../models/api.models';
import { ApiService } from './api.service';

const OPERATION_POLL_INTERVAL_MS = 1200;
const OPERATION_MAX_WAIT_MS = 90_000;

@Injectable({ providedIn: 'root' })
export class OperationPollerService {
  private readonly api = inject(ApiService);

  pollUntilTerminal(initial: OperationStatusResponse): Observable<OperationStatusResponse> {
    if (initial.state === 'SUCCEEDED' || initial.state === 'FAILED') {
      return of(initial);
    }

    return interval(OPERATION_POLL_INTERVAL_MS).pipe(
      switchMap(() => this.api.getOperationStatus(initial.operationId)),
      startWith(initial),
      takeWhile((op) => op.state === 'PENDING' || op.state === 'IN_PROGRESS', true),
      timeout(OPERATION_MAX_WAIT_MS)
    );
  }
}
