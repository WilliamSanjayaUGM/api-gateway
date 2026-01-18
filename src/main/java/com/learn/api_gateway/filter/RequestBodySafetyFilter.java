package com.learn.api_gateway.filter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.brotli.dec.BrotliInputStream;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.learn.api_gateway.util.BodySafetyLimits;
import com.learn.api_gateway.util.GatewayUtil;
import com.learn.api_gateway.util.WAFBootstrapUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Protect against: Oversized request bodies, gzip bombs, brotli bombs, zip bombs, parser DoS
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class RequestBodySafetyFilter implements GlobalFilter, Ordered{
	
	private final WAFBootstrapUtil waf;
	private final GatewayUtil gatewayUtil;
	
	@Override
	public int getOrder() {
		return -900;
	}
	
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		if (waf.isBootstrapPath(exchange)) {
            return chain.filter(exchange);
        }
		log.info("Goes pass RequestBodySafetyFilter------------");
		
		byte[] body = gatewayUtil.getCachedRequestBody(exchange);
		if (body == null) {
		    return chain.filter(exchange);
		}

		if (body.length > BodySafetyLimits.MAX_RAW_BYTES) {
		    return block(exchange, "Request body too large");
		}

		String encoding = Optional.ofNullable(
                exchange.getRequest().getHeaders()
                        .getFirst(HttpHeaders.CONTENT_ENCODING))
                .map(String::toLowerCase)
                .orElse("");

        MediaType contentType = exchange.getRequest().getHeaders().getContentType();
        log.info("--------RequestBodySafetyFilter encoding {}---",encoding);
        try {
            // 2 COMPRESSION CHECKS
            if (encoding.contains("gzip")) {
                inspectGzip(body);
            } else if (encoding.contains("br")) {
                inspectBrotli(body);
            }

            // 3 ZIP CHECK (CONTENT TYPE BASED)
            if (contentType != null &&
                contentType.toString().toLowerCase().contains("zip")) {
                inspectZip(body);
            }

        } catch (IllegalStateException ex) {
            log.warn("Body safety violation: {}", ex.getMessage());
            return block(exchange, ex.getMessage());
        } catch (Exception ex) {
            log.error("Body inspection failure", ex);
            return block(exchange, "Invalid request payload");
        }
        
        return chain.filter(exchange);
	}
	
	/* =========================================================
     * GZIP
     * ========================================================= */
    private void inspectGzip(byte[] compressed) throws Exception {
        if (compressed.length > BodySafetyLimits.MAX_COMPRESSED_BYTES) {
            throw new IllegalStateException("Compressed payload too large");
        }

        try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(compressed))) {

            streamInflation(gis);
        }
    }

    /* =========================================================
     * BROTLI
     * ========================================================= */
    private void inspectBrotli(byte[] compressed) throws Exception {

        if (compressed.length > BodySafetyLimits.MAX_COMPRESSED_BYTES) {
            throw new IllegalStateException("Compressed payload too large");
        }

        try (InputStream bis = new BrotliInputStream(new ByteArrayInputStream(compressed))) {

            streamInflation(bis);
        }
    }

    /* =========================================================
     * ZIP
     * ========================================================= */
    private void inspectZip(byte[] zipBytes) throws Exception {
    	log.info("----------RequestBodySafetyFilter inspectZip------");
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {

            long total = 0;
            int entries = 0;
            byte[] buf = new byte[8192];

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {

                if (++entries > BodySafetyLimits.MAX_ZIP_ENTRIES) {
                    throw new IllegalStateException("Too many ZIP entries");
                }

                int r;
                while ((r = zis.read(buf)) != -1) {
                    total += r;
                    if (total > BodySafetyLimits.MAX_INFLATED_BYTES) {
                        throw new IllegalStateException("ZIP bomb detected");
                    }
                }
            }
        }
    }

    /* =========================================================
     * SHARED STREAM INFLATION
     * ========================================================= */
    private void streamInflation(InputStream in) throws IOException {

        byte[] buf = new byte[8192];
        long total = 0;
        int read;

        while ((read = in.read(buf)) != -1) {
            total += read;
            if (total > BodySafetyLimits.MAX_INFLATED_BYTES) {
                throw new IllegalStateException("Decompression bomb detected");
            }
        }
    }

    private Mono<Void> block(ServerWebExchange exchange, String reason) {
        return waf.block(
                exchange,
                HttpStatus.BAD_REQUEST,
                reason
        );
    }
}
