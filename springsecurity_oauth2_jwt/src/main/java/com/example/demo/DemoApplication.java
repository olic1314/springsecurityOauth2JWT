package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.ComponentScan;

import java.util.Arrays;

@SpringBootApplication
@ComponentScan(basePackages = { "com.cmict.core", "com.example.demo" })
public class DemoApplication {

    public static void main(String[] args) {
//        SpringApplication application = new SpringApplication(DemoApplication.class);
//        application.setAllowBeanDefinitionOverriding(true);
//        application.run(args);

        ConfigurableApplicationContext run = SpringApplication.run(DemoApplication.class, args);
        String[] beanNames = run.getBeanDefinitionNames();
        System.out.println(Arrays.toString(beanNames));
    }
}
