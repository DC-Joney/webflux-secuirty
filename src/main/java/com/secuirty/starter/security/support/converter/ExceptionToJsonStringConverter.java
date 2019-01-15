package com.secuirty.starter.security.support.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.convert.converter.Converter;

public class ExceptionToJsonStringConverter implements Converter<Exception,String> {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String convert(Exception source) {
        try {
            return objectMapper.writeValueAsString(source.getMessage());
        } catch (JsonProcessingException e) {
            return e.getMessage();
        }
    }
}
