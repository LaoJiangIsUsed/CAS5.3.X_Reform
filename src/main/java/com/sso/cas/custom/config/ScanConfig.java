package com.sso.cas.custom.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * @ClassName: ScanConfig
 * @Description: cas 默认是扫描org.apereo.cas.web，这里需要添加自己的包位置使自定义controller可用
 * @Author: LaoJiang
 * @Date: 2020/2/13 0013 17:34
 * @Version: 1.0
 */
@Configuration
@ComponentScan("com.sso.cas.custom.controller")
public class ScanConfig {
}
