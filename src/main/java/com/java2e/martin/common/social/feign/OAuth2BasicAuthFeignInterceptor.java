package com.java2e.martin.common.social.feign;

import com.java2e.martin.common.core.constant.SecurityConstants;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;

/**
 * @author 狮少
 * @version 1.0
 * @date 2021/8/6
 * @describtion OAuth2BasicAuthFeignInterceptor
 * @since 1.0
 */
@Slf4j
@RefreshScope
public class OAuth2BasicAuthFeignInterceptor implements RequestInterceptor {
    @Value("${martin.feign.secret:123456}")
    private String secret;

    @Override
    public void apply(RequestTemplate requestTemplate) {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        //传递 token
        requestTemplate.header("Basic", "Y2xpZW50MjoxMjM0NTY=");
        log.debug("martin-inner secret:{}", secret);
        requestTemplate.header(SecurityConstants.MARTIN_INNER, secret);
    }

}
