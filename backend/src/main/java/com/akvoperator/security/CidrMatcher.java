package com.akvoperator.security;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * IPv4/IPv6 literal and CIDR matcher that strictly refuses hostname DNS lookups.
 */
public final class CidrMatcher {

    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)$"
    );
    private static final Pattern IPV6_ALLOWED_CHARS = Pattern.compile("^[0-9a-fA-F:]+$");

    private final byte[] networkBytes;
    private final int prefixLength;
    private final String originalCidr;

    private CidrMatcher(byte[] networkBytes, int prefixLength, String originalCidr) {
        this.networkBytes = networkBytes;
        this.prefixLength = prefixLength;
        this.originalCidr = originalCidr;
    }

    public static CidrMatcher parse(String cidrOrIp) {
        if (cidrOrIp == null || cidrOrIp.isBlank()) {
            throw new IllegalArgumentException("CIDR or IP address must not be blank");
        }
        String trimmed = cidrOrIp.trim();
        String ipPart;
        Integer prefix = null;

        int slashIndex = trimmed.indexOf('/');
        if (slashIndex >= 0) {
            ipPart = trimmed.substring(0, slashIndex).trim();
            String prefixStr = trimmed.substring(slashIndex + 1).trim();
            if (prefixStr.isEmpty() || trimmed.indexOf('/', slashIndex + 1) >= 0) {
                throw new IllegalArgumentException("Invalid CIDR notation: " + trimmed);
            }
            try {
                prefix = Integer.parseInt(prefixStr);
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("Invalid CIDR prefix length: " + trimmed, ex);
            }
        } else {
            ipPart = trimmed;
        }

        byte[] addrBytes = parseLiteralIp(ipPart);
        int maxBits = addrBytes.length * 8;
        int resolvedPrefix = prefix != null ? prefix : maxBits;
        if (resolvedPrefix < 0 || resolvedPrefix > maxBits) {
            throw new IllegalArgumentException("CIDR prefix out of range [0.." + maxBits + "]: " + trimmed);
        }
        return new CidrMatcher(addrBytes, resolvedPrefix, trimmed);
    }

    public boolean matches(String remoteIp) {
        if (remoteIp == null || remoteIp.isBlank()) {
            return false;
        }
        byte[] candidateBytes;
        try {
            candidateBytes = parseLiteralIp(stripZoneAndBrackets(remoteIp.trim()));
        } catch (IllegalArgumentException ex) {
            return false;
        }
        if (candidateBytes.length != networkBytes.length) {
            return false;
        }
        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        for (int i = 0; i < fullBytes; i++) {
            if (candidateBytes[i] != networkBytes[i]) {
                return false;
            }
        }
        if (remainingBits > 0) {
            int mask = 0xFF << (8 - remainingBits);
            return (candidateBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
        }
        return true;
    }

    public static boolean isLoopbackIpLiteral(String address) {
        if (address == null || address.isBlank()) {
            return false;
        }
        String normalized = stripZoneAndBrackets(address.trim());
        try {
            byte[] bytes = parseLiteralIp(normalized);
            return InetAddress.getByAddress(bytes).isLoopbackAddress();
        } catch (IllegalArgumentException | UnknownHostException ex) {
            return false;
        }
    }

    public String getOriginalCidr() {
        return originalCidr;
    }

    private static String stripZoneAndBrackets(String value) {
        String s = value;
        if (s.startsWith("[") && s.endsWith("]")) {
            s = s.substring(1, s.length() - 1);
        }
        int percentIdx = s.indexOf('%');
        if (percentIdx >= 0) {
            s = s.substring(0, percentIdx);
        }
        return s;
    }

    private static byte[] parseLiteralIp(String ip) {
        if (ip == null || ip.isEmpty()) {
            throw new IllegalArgumentException("IP literal is empty");
        }
        String cleaned = stripZoneAndBrackets(ip);
        boolean isIpv4 = IPV4_PATTERN.matcher(cleaned).matches();
        boolean isIpv6 = !isIpv4 && cleaned.contains(":") && IPV6_ALLOWED_CHARS.matcher(cleaned).matches();
        if (!isIpv4 && !isIpv6) {
            throw new IllegalArgumentException("Not a valid IPv4 or IPv6 literal: " + ip);
        }
        try {
            return InetAddress.getByName(cleaned).getAddress();
        } catch (UnknownHostException ex) {
            throw new IllegalArgumentException("Invalid IP literal: " + ip, ex);
        }
    }
}
