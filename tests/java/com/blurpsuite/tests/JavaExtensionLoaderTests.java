package com.blurpsuite.tests;

import com.blurpsuite.api.BurpExtenderCallbacksImpl;
import com.blurpsuite.core.ProxyServer;
import com.blurpsuite.extensions.JavaExtensionLoader;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static com.blurpsuite.tests.TestRunner.check;
import static com.blurpsuite.tests.TestRunner.eq;

/** Tests loading a concrete Java extension supplied as one compiled class file. */
public final class JavaExtensionLoaderTests {

    public void testLoadSingleClassFile() throws Exception {
        Path temp = Files.createTempDirectory("blurp-single-class");
        try {
            Path sourceDir = temp.resolve("src/com/blurpsuite/fixture");
            Files.createDirectories(sourceDir);
            Path source = sourceDir.resolve("SingleClassExtender.java");
            Files.writeString(source,
                    "package com.blurpsuite.fixture;\n"
                    + "import burp.IBurpExtender;\n"
                    + "import burp.IBurpExtenderCallbacks;\n"
                    + "public final class SingleClassExtender implements IBurpExtender {\n"
                    + "    @Override public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {\n"
                    + "        callbacks.setExtensionName(\"single-class-extender\");\n"
                    + "    }\n"
                    + "}\n", StandardCharsets.UTF_8);

            Path classes = temp.resolve("classes");
            Files.createDirectories(classes);
            var compiler = javax.tools.ToolProvider.getSystemJavaCompiler();
            check(compiler != null, "system Java compiler available");
            int compiled = compiler.run(null, null, null,
                    "-classpath", compilerClasspath(),
                    "-d", classes.toString(), source.toString());
            eq(compiled, 0, "fixture compiled");

            Path artifact = classes.resolve("com/blurpsuite/fixture/SingleClassExtender.class");
            check(Files.isRegularFile(artifact), "single class file exists");

            PrintStream out = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
            BurpExtenderCallbacksImpl callbacks = new BurpExtenderCallbacksImpl(
                    new ProxyServer(0, "127.0.0.1"), new String[0], out, out);
            try (JavaExtensionLoader.LoadedJavaExtension loaded =
                         JavaExtensionLoader.load(artifact, callbacks)) {
                eq(loaded.extenders().size(), 1, "one extender instantiated");
                eq(loaded.extenders().get(0).getClass().getName(),
                        "com.blurpsuite.fixture.SingleClassExtender", "fixture class loaded by name");
                eq(callbacks.extensionName(), "single-class-extender",
                        "registerExtenderCallbacks executed");
            } finally {
                callbacks.dispose();
            }
        } finally {
            deleteTree(temp);
        }
    }

    /**
     * Builds a javac classpath from the loaded classes' real code sources.
     * {@code java.class.path} is the Maven launcher's classpath under
     * {@code exec:java}, not the project classpath used to load TestRunner.
     */
    private static String compilerClasspath() throws Exception {
        List<String> entries = new ArrayList<>();
        appendCodeSource(entries, Class.forName("burp.IBurpExtender"));
        appendCodeSource(entries, JavaExtensionLoaderTests.class);
        String systemClasspath = System.getProperty("java.class.path", "");
        if (!systemClasspath.isBlank() && !entries.contains(systemClasspath)) {
            entries.add(systemClasspath);
        }
        return String.join(System.getProperty("path.separator"), entries);
    }

    private static void appendCodeSource(List<String> entries, Class<?> type) throws Exception {
        var codeSource = type.getProtectionDomain().getCodeSource();
        if (codeSource == null || codeSource.getLocation() == null) {
            return;
        }
        String entry = Paths.get(codeSource.getLocation().toURI()).toString();
        if (!entries.contains(entry)) {
            entries.add(entry);
        }
    }

    private static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (var stream = Files.walk(root)) {
            stream.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.delete(path);
                } catch (IOException ignored) {
                    // Best effort cleanup in a temporary directory.
                }
            });
        }
    }
}
