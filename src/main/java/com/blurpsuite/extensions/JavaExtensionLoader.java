package com.blurpsuite.extensions;

import burp.IBurpExtender;
import com.blurpsuite.api.ApiTrafficBridge;
import com.blurpsuite.api.BurpExtenderCallbacksImpl;

import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Loads compiled Java extensions from a JAR or a directory of class files. */
public final class JavaExtensionLoader {
    private JavaExtensionLoader() {
    }

    /** Loads every concrete IBurpExtender found in the given artifact. */
    public static LoadedJavaExtension load(Path artifact, BurpExtenderCallbacksImpl callbacks)
            throws Exception {
        Path normalized = artifact.toAbsolutePath().normalize();
        List<String> classNames = findClassNames(normalized);
        URL[] urls = {classPathRoot(normalized, classNames).toUri().toURL()};
        URLClassLoader loader = new URLClassLoader(urls, JavaExtensionLoader.class.getClassLoader());
        List<IBurpExtender> extenders = new ArrayList<>();
        List<String> failures = new ArrayList<>();

        for (String className : classNames) {
            try {
                Class<?> candidate = Class.forName(className, true, loader);
                if (!IBurpExtender.class.isAssignableFrom(candidate)
                        || Modifier.isAbstract(candidate.getModifiers())) {
                    continue;
                }
                Constructor<?> constructor = candidate.getDeclaredConstructor();
                constructor.setAccessible(true);
                extenders.add((IBurpExtender) constructor.newInstance());
            } catch (ClassNotFoundException | NoClassDefFoundError e) {
                // Missing optional dependencies are not fatal; keep scanning.
            } catch (ReflectiveOperationException | LinkageError | RuntimeException e) {
                failures.add(className + ": " + e);
            }
        }

        if (extenders.isEmpty()) {
            loader.close();
            throw new IOException("No concrete IBurpExtender implementation found in " + artifact
                    + (failures.isEmpty() ? "" : " (failures: " + failures + ")"));
        }
        for (IBurpExtender extender : extenders) {
            extender.registerExtenderCallbacks(callbacks);
        }
        callbacks.printOutput("loaded " + extenders.size() + " Java extender(s)");
        return new LoadedJavaExtension(loader, extenders);
    }

    private static List<String> findClassNames(Path artifact) throws IOException {
        List<String> names = new ArrayList<>();
        if (Files.isDirectory(artifact)) {
            try (var stream = Files.walk(artifact)) {
                stream.filter(path -> path.toString().endsWith(".class"))
                        .forEach(path -> names.add(toClassName(artifact.relativize(path).toString())));
            }
        } else if (artifact.toString().endsWith(".jar")) {
            try (JarFile jar = new JarFile(artifact.toFile())) {
                Enumeration<JarEntry> entries = jar.entries();
                while (entries.hasMoreElements()) {
                    String name = entries.nextElement().getName();
                    if (name.endsWith(".class") && !name.startsWith("META-INF/")) {
                        names.add(toClassName(name));
                    }
                }
            }
        } else if (artifact.toString().endsWith(".class")) {
            names.add(readBinaryName(artifact));
        }
        return names;
    }

    /**
     * A single class file is not a valid classpath entry; its package root is.
     * Directories and JARs remain their own classpath root.
     */
    private static Path classPathRoot(Path artifact, List<String> classNames) {
        if (Files.isDirectory(artifact) || !artifact.toString().endsWith(".class")
                || classNames.isEmpty()) {
            return artifact;
        }
        Path root = artifact.getParent();
        if (root == null) {
            return artifact;
        }
        int lastDot = classNames.get(0).lastIndexOf('.');
        if (lastDot >= 0) {
            int levels = classNames.get(0).substring(0, lastDot).split("\\.", -1).length;
            for (int i = 0; i < levels && root.getParent() != null; i++) {
                root = root.getParent();
            }
        }
        return root;
    }

    /** Reads the binary name from the class file's this_class constant pool entry. */
    private static String readBinaryName(Path classFile) throws IOException {
        try (DataInputStream in = new DataInputStream(Files.newInputStream(classFile))) {
            if (in.readInt() != 0xCAFEBABE) {
                throw new IOException("Not a Java class file: " + classFile);
            }
            in.readUnsignedShort(); // minor version
            in.readUnsignedShort(); // major version
            int count = in.readUnsignedShort();
            Object[] pool = new Object[count];
            for (int i = 1; i < count; i++) {
                int tag = in.readUnsignedByte();
                switch (tag) {
                    case 1 -> pool[i] = in.readUTF();
                    case 7 -> pool[i] = new ClassRef(in.readUnsignedShort());
                    case 3, 4, 9, 10, 11, 12, 17, 18 -> in.skipNBytes(4);
                    case 5, 6 -> {
                        in.skipNBytes(8);
                        i++; // long and double take two constant pool slots
                    }
                    case 8, 16, 19, 20 -> in.skipNBytes(2);
                    case 15 -> in.skipNBytes(3);
                    default -> throw new IOException(
                            "Unsupported constant pool tag " + tag + " in " + classFile);
                }
            }
            in.readUnsignedShort(); // access flags
            int thisClass = in.readUnsignedShort();
            if (thisClass <= 0 || thisClass >= pool.length
                    || !(pool[thisClass] instanceof ClassRef ref)
                    || !(pool[ref.nameIndex()] instanceof String name)) {
                throw new IOException("Cannot read class name from " + classFile);
            }
            return name.replace('/', '.');
        }
    }

    private record ClassRef(int nameIndex) {
    }

    private static String toClassName(String path) {
        return path.replace('\\', '/').replace('/', '.').replaceAll("\\.class$", "");
    }

    /** Holds the classloader so it can be closed when the extension is unloaded. */
    public static final class LoadedJavaExtension implements AutoCloseable {
        private final URLClassLoader loader;
        private final List<IBurpExtender> extenders;

        LoadedJavaExtension(URLClassLoader loader, List<IBurpExtender> extenders) {
            this.loader = loader;
            this.extenders = List.copyOf(extenders);
        }

        public List<IBurpExtender> extenders() {
            return extenders;
        }

        @Override
        public void close() throws IOException {
            loader.close();
        }
    }
}
