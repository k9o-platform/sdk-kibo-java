package dev.k9o.kibo;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Surface tests for the Kibo Java facade. The crypto round-trip (incl. the
 * posture-floor rejection path) needs the CI-injected uniffi binding + native
 * lib and is exercised in CI; the same behaviour is proven against the real
 * core in the Ruby ({@code K9o::Kibo}) and Python ({@code k9o.kibo}) suites,
 * which share the identical {@code zk_*_blocking} export. Here we pin the
 * public facade shape so a regression is caught even without the native lib.
 */
class KiboTest {

    @Test
    void facadeExposesStaticEncryptAndDecrypt() throws NoSuchMethodException {
        for (String name : new String[] { "encrypt", "decrypt" }) {
            Method m = findMethod(name);
            assertTrue(Modifier.isStatic(m.getModifiers()), name + " must be static");
            assertTrue(Modifier.isPublic(m.getModifiers()), name + " must be public");
        }
    }

    private static Method findMethod(String name) throws NoSuchMethodException {
        for (Method m : Kibo.class.getDeclaredMethods()) {
            if (m.getName().equals(name)) {
                return m;
            }
        }
        throw new NoSuchMethodException(name);
    }
}
