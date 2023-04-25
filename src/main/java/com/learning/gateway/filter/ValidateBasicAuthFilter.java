package com.learning.gateway.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.*;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;

@Component
@Order(10)
public class ValidateBasicAuthFilter implements GatewayFilter {

    @Autowired
    RestTemplate restTemplate;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        try{
            if(exchange.getRequest().getHeaders().containsKey("Authorization")){
                String requestTokenHeader = exchange.getRequest().getHeaders().get("Authorization").get(0);
                if(requestTokenHeader != null && requestTokenHeader.startsWith("Basic ")){
                    String basicToken = requestTokenHeader.substring(6);
                    String url = "http://localhost:8083/auth/oauth/token/check_client?token=" + basicToken;
                    HttpHeaders headers = new HttpHeaders();
                    headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
                    HttpEntity<String> entity = new HttpEntity<>(headers);
                    boolean checkClientToken;
                    try{
                        checkClientToken = restTemplate.exchange(url, HttpMethod.POST, entity, Boolean.class).getBody();
                    }catch (HttpStatusCodeException e){
                        return this.onError(exchange,e.getResponseBodyAsString(),e.getStatusCode());
                    }
                    if(!checkClientToken){
                        return this.onError(exchange,"Invalid client token",HttpStatus.UNAUTHORIZED);
                    }
                    return chain.filter(exchange);
                }
                return this.onError(exchange,"No Authorization Header",HttpStatus.UNAUTHORIZED);
            }
            return this.onError(exchange,"No Authorization Header",HttpStatus.UNAUTHORIZED);
        }catch (Exception e){
            return this.onError(exchange,"No Authorization Header",HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus){
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        DataBufferFactory dataBufferFactory = exchange.getResponse().bufferFactory();
        return response.writeWith(Mono.just(err.getBytes()).map(r -> dataBufferFactory.wrap(r)));
    }
}
