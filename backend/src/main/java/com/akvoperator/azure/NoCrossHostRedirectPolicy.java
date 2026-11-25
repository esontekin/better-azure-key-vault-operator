package com.akvoperator.azure;

import com.akvoperator.common.exception.AppException;
import com.azure.core.http.HttpPipelineCallContext;
import com.azure.core.http.HttpPipelinePosition;
import com.azure.core.http.HttpResponse;
import com.azure.core.http.policy.HttpPipelineSyncPolicy;
import org.springframework.http.HttpStatus;

import java.util.Set;

/**
 * HTTP pipeline policy that blocks HTTP redirect responses (301/302/303/307/308) from Azure endpoints
 * so bearer tokens or authorization headers can never be forwarded to an untrusted host via redirect.
 */
public class NoCrossHostRedirectPolicy extends HttpPipelineSyncPolicy {

    private static final Set<Integer> REDIRECT_STATUS_CODES = Set.of(301, 302, 303, 307, 308);

    @Override
    public HttpPipelinePosition getPipelinePosition() {
        return HttpPipelinePosition.PER_RETRY;
    }

    @Override
    protected HttpResponse afterReceivedResponse(HttpPipelineCallContext context, HttpResponse response) {
        if (response != null && REDIRECT_STATUS_CODES.contains(response.getStatusCode())) {
            try {
                response.close();
            } catch (Exception ignored) {
                // Best-effort close before aborting the redirected call
            }
            throw AppException.azureUpstreamError(
                    HttpStatus.BAD_GATEWAY,
                    "Upstream Azure endpoint returned an HTTP redirect which was blocked to prevent credential forwarding.",
                    null
            );
        }
        return response;
    }
}
