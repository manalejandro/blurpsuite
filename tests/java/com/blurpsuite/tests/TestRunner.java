package com.blurpsuite.tests;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;

/** Minimal dependency-free test runner: discovers public void test*() methods. */
public final class TestRunner {
    private static int passed;
    private static int failed;

    private TestRunner() {
    }

    public static void main(String[] args) throws Exception {
        String[] classes = args.length > 0 ? args : new String[]{
                "com.blurpsuite.tests.CoreTests",
                "com.blurpsuite.tests.ApiTests",
                "com.blurpsuite.tests.JavaExtensionLoaderTests",
                "com.blurpsuite.tests.JrpcConnectionTests",
        };
        for (String className : classes) {
            Class<?> type = Class.forName(className);
            Object instance = type.getDeclaredConstructor().newInstance();
            Method[] methods = type.getDeclaredMethods();
            Arrays.sort(methods, (a, b) -> a.getName().compareTo(b.getName()));
            for (Method method : methods) {
                if (!method.getName().startsWith("test") || method.getParameterCount() != 0) {
                    continue;
                }
                try {
                    method.invoke(instance);
                    passed++;
                    System.out.println("PASS  " + className + "." + method.getName());
                } catch (InvocationTargetException e) {
                    failed++;
                    Throwable cause = e.getCause();
                    System.out.println("FAIL  " + className + "." + method.getName()
                            + ": " + cause);
                    cause.printStackTrace(System.out);
                }
            }
        }
        System.out.println();
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0) {
            System.exit(1);
        }
    }

    public static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    public static void eq(Object actual, Object expected, String message) {
        if (!java.util.Objects.equals(actual, expected)) {
            throw new AssertionError(message + ": expected <" + expected + "> but was <" + actual + ">");
        }
    }

    public static void eqBytes(byte[] actual, byte[] expected, String message) {
        if (!Arrays.equals(actual, expected)) {
            throw new AssertionError(message + ": expected "
                    + Arrays.toString(expected) + " but was " + Arrays.toString(actual));
        }
    }

    public static void throwsIllegalArgument(Runnable action, String message) {
        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError(message + ": expected IllegalArgumentException");
    }
}
