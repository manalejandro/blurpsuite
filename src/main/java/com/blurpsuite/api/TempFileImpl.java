package com.blurpsuite.api;

import burp.ITempFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** A buffer persisted to a temporary file. */
public final class TempFileImpl implements ITempFile {
    private final Path path;

    public TempFileImpl(byte[] buffer) throws IOException {
        this.path = Files.createTempFile("blurp-", ".bin");
        Files.write(path, buffer);
        path.toFile().deleteOnExit();
    }

    @Override
    public byte[] getBuffer() {
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read temp file", e);
        }
    }

    @Override
    public void delete() {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // Best effort cleanup.
        }
    }
}
