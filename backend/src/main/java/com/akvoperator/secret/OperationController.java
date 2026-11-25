package com.akvoperator.secret;

import com.akvoperator.common.dto.OperationStatusResponse;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST endpoint for polling principal- and vault-scoped asynchronous soft-delete / recover operations.
 */
@RestController
@RequestMapping("/api/v1/operations")
public class OperationController {

    private final AsyncOperationTracker operationTracker;

    public OperationController(AsyncOperationTracker operationTracker) {
        this.operationTracker = operationTracker;
    }

    @GetMapping("/{id}")
    public ResponseEntity<OperationStatusResponse> getOperationStatus(@PathVariable("id") String operationId) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(operationTracker.getOperationStatus(operationId));
    }
}
