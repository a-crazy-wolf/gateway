package com.learning.gateway.filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Map;

@Component
@Order(10)
public class ValidateOAuthFilter implements GatewayFilter {

    @Autowired
    RestTemplate restTemplate;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        try{
            if(exchange.getRequest().getHeaders().containsKey("Authorization")){
                String requestTokenHeader = exchange.getRequest().getHeaders().get("Authorization").get(0);
                if(requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")){
                    String accessToken = requestTokenHeader.substring(7);
                    String url = "http://localhost:8083/auth/oauth/check_token?token=" + accessToken;
                    HttpHeaders headers = new HttpHeaders();
                    headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
                    HttpEntity<String> entity = new HttpEntity<>(headers);
                    Map<String,Object> checkToken;
                    try{
                        checkToken = restTemplate.exchange(url, HttpMethod.POST, entity, Map.class).getBody();
                    }catch (HttpStatusCodeException e){
                        return this.onError(exchange,e.getResponseBodyAsString(),e.getStatusCode());
                    }
                    if(checkToken == null){
                        return this.onError(exchange,"Invalid token",HttpStatus.UNAUTHORIZED);
                    }
                    String userId = String.valueOf(checkToken.get("userId"));
                    ServerHttpRequest request = exchange.getRequest()
                            .mutate()
                            .header("userId",userId)
                            .build();
                    ServerWebExchange exchange1 = exchange.mutate().request(request).build();
                    return chain.filter(exchange1);
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
