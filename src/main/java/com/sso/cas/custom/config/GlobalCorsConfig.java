package com.sso.cas.custom.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * @author Administrator
 */
@Configuration
public class GlobalCorsConfig {
    @Bean
    public FilterRegistrationBean corsFilter(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowCredentials(true);
        //config.addAllowedOrigin("*");
        config.addAllowedOrigin("http://ssoclietone.one.com:9998");
        config.addAllowedOrigin("http://ssocliettwo.two.com:9997");
//        config.addAllowedHeader("Cookie");
//        config.addAllowedHeader("tempToken");
//        config.addAllowedHeader("token");
        config.addAllowedMethod("*");
//        config.addAllowedMethod(RequestMethod.GET.name());
//        config.addAllowedMethod(RequestMethod.POST.name());
//        config.addAllowedMethod(RequestMethod.PUT.name());
//        config.addAllowedMethod(RequestMethod.DELETE.name());

        // CORS 配置对所有接口都有效
        source.registerCorsConfiguration("/**", config);
        FilterRegistrationBean filter = new FilterRegistrationBean(new CorsFilter(source));
        // 跨域的过滤器应该比较靠前
        filter.setOrder(Integer.MIN_VALUE + 1);
        return filter;

    }
}
