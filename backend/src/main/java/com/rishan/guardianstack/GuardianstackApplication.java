package com.rishan.guardianstack;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main application class for GuardianStack
 *
 * @EnableAsync - Enables asynchronous processing for audit logs and email
 * @EnableScheduling - Enables scheduled tasks for token cleanup
 */
@SpringBootApplication
@EnableAsync
@EnableScheduling
public class GuardianstackApplication {

	public static void main(String[] args) {
		SpringApplication.run(GuardianstackApplication.class, args);
	}
}