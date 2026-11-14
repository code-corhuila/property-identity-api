package co.edu.corhuila.property.identity.app;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** A key given inline (one line with literal \n escapes, as a .env file holds it) or as a file. */
final class Pem {

    private Pem() { }

    static String read(String inline, String file) throws IOException {
        if (inline != null && !inline.isBlank()) {
            return inline.replace("\\n", "\n");
        }
        return file != null && !file.isBlank() ? Files.readString(Path.of(file)) : "";
    }
}
