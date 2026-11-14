package co.edu.corhuila.property.identity.app;

import java.util.Optional;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "co.edu.corhuila.property.identity")
public class IdentityApplication {
    public static void main(String[] args) {
        // HU-IDENT-004: the same jar issues a service token and exits, without the web server.
        Optional<String> serviceSubject = ServiceTokenCommand.subject(args);
        if (serviceSubject.isPresent()) {
            System.exit(ServiceTokenCommand.run(serviceSubject.get(), System.getenv(), System.out, System.err));
        }
        SpringApplication.run(IdentityApplication.class, args);
    }
}
