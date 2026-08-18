package org.jarsentinel.core;

import java.util.List;

/**
 * Registry of well-known, trusted open-source third-party libraries to suppress false-positive alerts.
 */
public class LibraryWhitelist {

    private static final List<String> WHITELISTED_PREFIXES = List.of(
            "org/tukaani/xz/",                      // XZ Compression library (XOR is for bit math)
            "de/maxhenkel/voicechat/concentus/",    // Concentus Opus audio codec (XOR is for audio encoding)
            "net/datafaker/",                       // Datafaker test generator (reflection is for schema generation)
            "org/slf4j/",                           // Logging framework
            "org/apache/logging/",                  // Log4j
            "com/google/gson/",                     // JSON parser
            "org/spongepowered/asm/",               // Sponge Mixin framework
            "com/mojang/"                           // Official Mojang code
    );

    public static boolean isWhitelistedPackage(String className) {
        if (className == null) return false;
        for (String prefix : WHITELISTED_PREFIXES) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
