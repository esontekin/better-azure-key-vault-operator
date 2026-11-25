package com.akvoperator.auth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Forwards known Angular SPA client routes to index.html without ever swallowing /api/** or /actuator/** paths.
 */
@Controller
public class SpaFallbackController {

    @GetMapping({
            "/login",
            "/vaults",
            "/vaults/{vaultId}",
            "/vaults/{vaultId}/secrets",
            "/vaults/{vaultId}/deleted-secrets",
            "/deleted-secrets",
            "/settings"
    })
    public String forwardToSpaIndex() {
        return "forward:/index.html";
    }
}
