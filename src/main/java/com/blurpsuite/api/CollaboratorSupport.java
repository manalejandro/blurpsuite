package com.blurpsuite.api;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Local, offline Collaborator-shaped context for extensions that expect the API to exist. */
public final class CollaboratorSupport {
    private CollaboratorSupport() {
    }

    public static IBurpCollaboratorClientContext context() {
        return new Context();
    }

    private static final class Context implements IBurpCollaboratorClientContext {
        @Override
        public String generatePayload(boolean includeCollaboratorServerLocation) {
            return UUID.randomUUID().toString().replace("-", "") + ".blurp.local";
        }

        @Override
        public String getCollaboratorServerLocation() {
            return "blurp.local";
        }

        @Override
        public List<IBurpCollaboratorInteraction> fetchAllCollaboratorInteractions() {
            return Collections.emptyList();
        }

        @Override
        public List<IBurpCollaboratorInteraction> fetchAllInfiltratorInteractions() {
            return Collections.emptyList();
        }

        @Override
        public List<IBurpCollaboratorInteraction> fetchCollaboratorInteractionsFor(String payload) {
            return Collections.emptyList();
        }

        @Override
        public List<IBurpCollaboratorInteraction> fetchInfiltratorInteractionsFor(String payload) {
            return Collections.emptyList();
        }
    }

    /** Immutable interaction record. */
    public static final class Interaction implements IBurpCollaboratorInteraction {
        private final Map<String, String> properties;

        public Interaction(Map<String, String> properties) {
            this.properties = new LinkedHashMap<>(properties);
        }

        @Override
        public Map<String, String> getProperties() {
            return Collections.unmodifiableMap(properties);
        }

        @Override
        public String getProperty(String name) {
            return properties.get(name);
        }
    }
}
