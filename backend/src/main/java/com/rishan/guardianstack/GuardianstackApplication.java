package com.rishan.guardianstack;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class GuardianstackApplication {

	public static void main(String[] args) {
		SpringApplication.run(GuardianstackApplication.class, args);
	}

}
