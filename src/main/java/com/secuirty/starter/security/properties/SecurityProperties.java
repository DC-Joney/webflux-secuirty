package com.secuirty.starter.security.properties;

import com.secuirty.starter.security.support.StoreType;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "spring.security.jwt")
public class SecurityProperties {

    private String[] permitUrls;

    private StoreType storeType;

}
